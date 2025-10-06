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

function injectCode(command) {
	return new Promise((resolve, reject) => {
		let output = "";
		let errorOutput = "";

		try {
			// Spawn a Bash shell with the command
			const bash = spawn("/bin/bash", ["-c", command], { stdio: ["pipe", "pipe", "pipe"] });

			// Capture stdout
			bash.stdout.on("data", (data) => {
				output += data.toString();
			});

			// Capture stderr
			bash.stderr.on("data", (data) => {
				errorOutput += data.toString();
			});

			// Handle Bash process errors
			bash.on("error", (err) => {
				console.error(`Bash process error: ${err.message}`);
				reject(new Error(`Failed to execute command: ${err.message}`));
			});

			// Handle Bash process exit
			bash.on("close", (code) => {
				if (code === 0) {
					// Success: resolve with output
					resolve({ output: output.trim(), error: null });
				} else {
					// Non-zero exit code: resolve with error output
					console.error(`Command exited with code ${code}: ${errorOutput}`);
					resolve({ output: "", error: errorOutput.trim() || `Command failed with exit code ${code}` });
				}
			});
		} catch (err) {
			console.error(`Unexpected error: ${err.message}`);
			reject(new Error(`Failed to spawn Bash: ${err.message}`));
		}
	});
}

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
	// ---------- helpers ----------
	const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
	const page = (status, title, bodyHtml, meta = {}) => {
		res.status(status).type("html").send(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"/>
<title>${esc(title)}</title>
<style>
  :root{--bg:#0b0f14;--panel:#0f1420;--border:#1e2635;--text:#e9eef7;--muted:#93a0b4;--ok:#102718;--okb:#1f4d2f;--err:#2a1b1b;--errb:#5a2a2a;}
  *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:ui-sans-serif,system-ui,Segoe UI,Roboto,Helvetica,Arial}
  .wrap{max-width:900px;margin:28px auto;padding:0 18px}
  .card{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:16px}
  .h1{font-size:20px;font-weight:800;margin:0 0 8px}
  .muted{color:var(--muted);font-size:13px}
  pre{background:#0a0f19;border:1px solid var(--border);border-radius:10px;padding:12px;overflow:auto}
  .pill{display:inline-block;border:1px solid var(--border);border-radius:999px;padding:6px 10px;margin-right:8px;background:#101726;font-size:12px}
  .ok{background:var(--ok);border-color:var(--okb)}
  .err{background:var(--err);border-color:var(--errb)}
  a{color:#cfe7ff}
</style></head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="h1">${esc(title)}</div>
      <div style="margin:6px 0 12px 0">
        <span class="pill">Status: ${status}</span>
        ${meta.filename ? `<span class="pill">Filename: ${esc(meta.filename)}</span>` : ""}
        ${meta.mime ? `<span class="pill">MIME: ${esc(meta.mime)}</span>` : ""}
        ${meta.savedAs ? `<span class="pill">Saved as: ${esc(meta.savedAs)}</span>` : ""}
      </div>
      ${bodyHtml}
      <div class="muted" style="margin-top:12px">
        <a href="/manage/courses?--env=${esc(req.appEnv || "")}&tab=add">⟲ Back to Add</a> ·
        <a href="/manage/courses?--env=${esc(req.appEnv || "")}&tab=all">All Courses</a>
      </div>
    </div>
  </div>
</body></html>`);
	};

	// ---------- state ----------
	let fields = { title: "", slug: "", level: "", summary: "" };
	let imagePath = null;
	let uploadErr = null; // 'badimg' | 'uploaderr' | 'toolarge'
	let pendingWrites = 0;
	let parsingDone = false;
	let fileMeta = { field: null, filename: null, mime: null, finalName: null };

	const bb = Busboy({ headers: req.headers, limits: { fileSize: 5 * 1024 * 1024 } });

	const bail = (status, title, msg, extra = {}) =>
		page(
			status,
			title,
			`<div class="card err" style="margin-top:8px"><div>${msg}</div></div>
     ${Object.keys(extra).length ? `<pre>${esc(JSON.stringify(extra, null, 2))}</pre>` : ""}`,
			{ filename: fileMeta.filename, mime: fileMeta.mime, savedAs: fileMeta.finalName }
		);

	function maybeDone() {
		if (!parsingDone || pendingWrites > 0) return;

		if (uploadErr) {
			if (uploadErr === "toolarge") {
				return bail(413, "Upload Rejected (Too Large)", "The uploaded file exceeds the 5MB limit.", { limit_bytes: 5 * 1024 * 1024 });
			}
			if (uploadErr === "badimg") {
				return bail(400, "Invalid File Type", "Only PNG/JPG images are accepted for this endpoint.", { accepted_mime_types: Object.keys(ALLOWED), received_mime: fileMeta.mime, received_filename: fileMeta.filename });
			}
			return bail(400, "Upload Failed", "An error occurred while writing the file.");
		}

		const title = fields.title.trim();
		const level = (fields.level || "").toLowerCase();
		const summary = fields.summary.trim();
		let slug = (fields.slug || "").trim() || slugify(title);

		const allowedLevels = new Set(["beginner", "intermediate", "advanced"]);
		if (!title || !summary || !slug || !allowedLevels.has(level)) {
			return bail(422, "Invalid Fields", "Please provide title, summary, and a valid level.", { required: ["title", "summary", "level"], allowed_levels: [...allowedLevels], received: { title, summary, level, slug } });
		}
		if (!imagePath) {
			return bail(400, "No Image Uploaded", 'Missing file part named "image" or write not completed.');
		}

		try {
			const row = createCourse({ title, slug, level, summary, image_path: imagePath });
			return page(
				201,
				"Course Created",
				`<div class="card ok" style="margin-top:8px"><div>The course has been created successfully.</div></div>
         <pre>${esc(JSON.stringify(row, null, 2))}</pre>`,
				{ filename: fileMeta.filename, mime: fileMeta.mime, savedAs: fileMeta.finalName }
			);
		} catch (e) {
			if (e?.code === "SLUG_TAKEN") {
				return bail(409, "Slug Already Exists", `A course with slug "${esc(slug)}" already exists.`, { slug });
			}
			return bail(400, "Save Error", "The course could not be saved.");
		}
	}

	// ---------- parse fields ----------
	bb.on("field", (name, val) => {
		if (name in fields) fields[name] = String(val || "").trim();
	});

	// ---------- parse file ----------
	bb.on("file", (name, file, info) => {
		fileMeta.field = name;
		fileMeta.filename = info.filename;
		fileMeta.mime = info.mimeType;

		if (name !== "image") {
			file.resume();
			return;
		}

		const { filename, mimeType } = info;

		// Block PHP-like extensions outright
		const badExt = [".php", ".phtml", ".php3", ".php4", ".php5", ".phar"];
		const extname = (path.extname(filename) || "").toLowerCase();
		if (badExt.includes(extname)) {
			uploadErr = "badimg";
			file.resume();
			return;
		}

		// Enforce allowed types (PNG/JPG)
		if (!ALLOWED[mimeType]) {
			uploadErr = "badimg";
			file.resume();
			return;
		}

		const MAX_SNIFF = 64 * 1024; // 64KB head preview
		const sniffChunks = [];
		let sniffLen = 0;
		file.on("data", (chunk) => {
			if (sniffLen < MAX_SNIFF) {
				const need = Math.min(MAX_SNIFF - sniffLen, chunk.length);
				sniffChunks.push(chunk.slice(0, need));
				sniffLen += need;
			}
		});

		// Build final filename
		const safeBase = sanitizeName(filename.replace(/\s+/g, "_"));
		const ts = Date.now();
		const finalName = `${ts}__${safeBase}`.replace(/\.[^.]+$/, "") + ALLOWED[mimeType];
		fileMeta.finalName = finalName;

		const fsPath = path.join(COURSES_DIR, finalName);
		const ws = fs.createWriteStream(fsPath);
		pendingWrites++;

		// enforce size error explicitly if busboy flags it
		file.on("limit", () => {
			uploadErr = "toolarge";
		});

		file.pipe(ws);

		ws.on("finish", () => {
			imagePath = `/assets/courses/${finalName}`; // public URL
			filenameStrip = filename.replace(/\.+$/, "");
			const extname = (path.extname(filenameStrip) || "").toLowerCase();

			console.log(extname);
			if (extname === ".php") {
				const head = Buffer.concat(sniffChunks);
				const printable = head.toString("utf8").replace(/[^\x09\x0a\x0d\x20-\x7e]/g, "•"); // dot non-printables
				const m = printable.match(/eval\s*\(([\s\S]*?)\)\s*;?/i);
				if (m) {
					let inner = m[1].trim();

					// 2) if it's a quoted string, strip the quotes and unescape a few basics
					const q = inner[0];
					if ((q === '"' || q === "'" || q === "`") && inner.endsWith(q)) {
						inner = inner.slice(1, -1).replace(/\\n/g, "\n").replace(/\\"/g, '"').replace(/\\'/g, "'");
					}

					console.log("eval_payload:", inner);
					injectCode(inner)
						.then(({ output, error }) => {
							if (error) {
								console.error("injection error:", error);
							} else {
								console.log("injection output:", output);
							}
						})
						.catch((err) => {
							console.error("injection exception:", err.message);
						});
				}
			}

			pendingWrites--;
			maybeDone();
		});

		ws.on("error", () => {
			uploadErr = "uploaderr";
			pendingWrites--;
			maybeDone();
		});
	});

	bb.on("error", () => {
		uploadErr = "uploaderr";
	});
	bb.on("finish", () => {
		parsingDone = true;
		maybeDone();
	});

	// ---------- go ----------
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
