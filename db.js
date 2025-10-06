// db.js
const fs = require("fs");
const path = require("path");
const Database = require("better-sqlite3");
const crypto = require("crypto");

const DATA_DIR = path.join(__dirname, "data");
const DB_PATH = path.join(DATA_DIR, "app.db");
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);

const db = new Database(DB_PATH);

// ---------- USERS ----------
db.exec(`
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT UNIQUE NOT NULL,
    pass_hash  TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    role       TEXT NOT NULL DEFAULT 'user'
  );
`);

// MD5 (intentionally weak for cracking practice)
function md5Hex(s) {
	return crypto.createHash("md5").update(s, "utf8").digest("hex");
}

function ensureUser(username, pwd, role = "user") {
	const row = db.prepare("SELECT id FROM users WHERE username=?").get(username);
	if (!row) {
		const hash = md5Hex(pwd);
		db.prepare("INSERT INTO users (username, pass_hash, role) VALUES (?,?,?)").run(username, hash, role);
		console.log(`[db] seeded -> ${username}/${pwd} (role=${role}, md5=${hash})`);
	}
}
ensureUser("admin", "admin123", "admin");
ensureUser("devuser", "dev123", "dev");

function findUser(username) {
	return db.prepare("SELECT id, username, pass_hash, role, created_at FROM users WHERE username=?").get(username);
}
function listUsers() {
	return db.prepare("SELECT id, username, role, pass_hash, created_at FROM users ORDER BY id").all();
}
async function verifyPassword(plain, hash) {
	return md5Hex(plain) === hash;
}

/** Register a new user (role defaults to 'user'). Throws USERNAME_TAKEN on dup. */
function registerUser(username, password, role = "user") {
	const u = String(username || "").trim();
	if (!u) throw new Error("USERNAME_REQUIRED");
	if (!password) throw new Error("PASSWORD_REQUIRED");

	const pass_hash = md5Hex(password);
	try {
		const info = db.prepare("INSERT INTO users (username, pass_hash, role) VALUES (?,?,?)").run(u, pass_hash, role);
		return db.prepare("SELECT id, username, pass_hash, role, created_at FROM users WHERE id=?").get(info.lastInsertRowid);
	} catch (err) {
		if (String(err.message).includes("UNIQUE") || String(err.code) === "SQLITE_CONSTRAINT_UNIQUE") {
			const e = new Error("USERNAME_TAKEN");
			e.cause = err;
			throw e;
		}
		throw err;
	}
}

// ---------- COURSES ----------
db.exec(`
  CREATE TABLE IF NOT EXISTS courses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title      TEXT NOT NULL,
    slug       TEXT UNIQUE NOT NULL,
    level      TEXT NOT NULL,       -- beginner | intermediate | advanced
    summary    TEXT NOT NULL,
    image_path TEXT NOT NULL,       -- URL path under /assets, e.g. /assets/courses/recon.jpg
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// NOTE on image paths:
// - Filesystem upload/save path:    ./public/courses/<filename>
// - Public URL for templates:       /assets/courses/<filename>
//   (because app.use("/assets", express.static(path.join(__dirname, "public"))) )

// Seed a few demo courses once
const ccount = db.prepare("SELECT COUNT(*) AS n FROM courses").get().n;
if (ccount === 0) {
	const seedCourses = [
		{
			title: "Recon & Enumeration 101",
			slug: "recon-enum-101",
			level: "beginner",
			summary: "Subdomains, directories, service discovery, and note-taking.",
			image_path: "/assets/courses/recon.jpg",
		},
		{
			title: "Web Exploitation Essentials",
			slug: "web-exploitation-essentials",
			level: "intermediate",
			summary: "SSTI, SQLi, file uploads, and auth logic pitfalls—with fixes.",
			image_path: "/assets/courses/web.jpg",
		},
		{
			title: "Privilege Escalation Playbook",
			slug: "privesc-playbook",
			level: "advanced",
			summary: "Linux/Windows privesc, creds hunting, and misconfig chains.",
			image_path: "/assets/courses/privesc.jpg",
		},
	];
	const insert = db.prepare(`
    INSERT INTO courses (title, slug, level, summary, image_path)
    VALUES (@title, @slug, @level, @summary, @image_path)
  `);
	const tx = db.transaction((arr) => arr.forEach((c) => insert.run(c)));
	tx(seedCourses);
	console.log("[db] seeded demo courses (3)");
}

// Course helpers
function listCourses() {
	return db.prepare("SELECT id, title, slug, level, summary, image_path FROM courses ORDER BY id").all();
}
function findCourseById(id) {
	return db.prepare("SELECT id, title, slug, level, summary, image_path FROM courses WHERE id=?").get(id);
}
function deleteCourseById(id) {
	return db.prepare("DELETE FROM courses WHERE id=?").run(id); // -> { changes }
}
/** Create a course; throws SLUG_TAKEN on duplicate slug. */
function createCourse({ title, slug, level, summary, image_path }) {
	const exists = db.prepare("SELECT 1 FROM courses WHERE slug=?").get(slug);
	if (exists) {
		const e = new Error("SLUG_TAKEN");
		e.code = "SLUG_TAKEN";
		throw e;
	}
	const stmt = db.prepare(`
    INSERT INTO courses (title, slug, level, summary, image_path)
    VALUES (?, ?, ?, ?, ?)
  `);
	const info = stmt.run(title, slug, level, summary, image_path);
	return db.prepare("SELECT id, title, slug, level, summary, image_path, created_at FROM courses WHERE id=?").get(info.lastInsertRowid);
}

module.exports = {
	db,
	// users
	findUser,
	listUsers,
	verifyPassword,
	registerUser,
	// courses
	listCourses,
	findCourseById,
	deleteCourseById,
	createCourse,
};
