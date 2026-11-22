import json
import os
import secrets
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DATA_FILE = os.path.join(DATA_DIR, "portfolio.json")
AUTH_FILE = os.path.join(DATA_DIR, "auth.json")
SECRET_FILE = os.path.join(DATA_DIR, ".secret_key")


def get_or_create_secret_key():
    if os.environ.get("FLASK_SECRET_KEY"):
        return os.environ["FLASK_SECRET_KEY"]
    if os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, "r", encoding="utf-8") as f:
            key = f.read().strip()
            if key:
                return key
    key = secrets.token_hex(32)
    with open(SECRET_FILE, "w", encoding="utf-8") as f:
        f.write(key)
    return key


app.secret_key = get_or_create_secret_key()


def load_data():
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_data(data):
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def load_auth():
    if not os.path.exists(AUTH_FILE):
        default_auth = {
            "username": "dwi",
            "password_hash": generate_password_hash("dwi12345")
        }
        save_auth(default_auth)
        return default_auth
    with open(AUTH_FILE, "r", encoding="utf-8") as f:
        auth = json.load(f)
    if not auth.get("password_hash"):
        auth["username"] = auth.get("username") or "dwi"
        auth["password_hash"] = generate_password_hash("dwi12345")
        save_auth(auth)
    return auth


def save_auth(auth_data):
    with open(AUTH_FILE, "w", encoding="utf-8") as f:
        json.dump(auth_data, f, ensure_ascii=False, indent=2)


# Ensure default credentials exist at startup
load_auth()


def login_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if not session.get("is_admin"):
            flash("Silakan login sebagai pemilik terlebih dahulu untuk mengakses halaman edit.", "error")
            return redirect(url_for("login", next=request.path))
        return view_func(*args, **kwargs)
    return wrapped_view


@app.context_processor
def inject_global_data():
    data = load_data()
    return dict(
        profile=data["profile"],
        is_admin=bool(session.get("is_admin"))
    )


@app.route("/")
def index():
    data = load_data()
    return render_template("index.html", data=data, active_page="home")


@app.route("/about")
def about():
    data = load_data()
    return render_template("about.html", data=data, active_page="about")


@app.route("/projects")
def projects():
    data = load_data()
    return render_template("projects.html", data=data, active_page="projects")


@app.route("/contact", methods=["GET", "POST"])
def contact():
    data = load_data()
    if request.method == "POST":
        sender_name = request.form.get("name", "").strip()
        sender_email = request.form.get("email", "").strip()
        message = request.form.get("message", "").strip()
        if sender_name and sender_email and message:
            flash(f"Terima kasih {sender_name}, pesan Anda telah diterima dan akan segera dibalas.", "success")
            return redirect(url_for("contact"))
        else:
            flash("Mohon lengkapi nama, email, dan pesan Anda.", "error")
    return render_template("contact.html", data=data, active_page="contact")


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("is_admin"):
        return redirect(url_for("admin"))

    data = load_data()
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        auth = load_auth()

        if username == auth.get("username") and check_password_hash(auth.get("password_hash", ""), password):
            session["is_admin"] = True
            session["admin_user"] = username
            flash("Login berhasil! Selamat datang kembali di mode pengelola.", "success")
            next_url = request.args.get("next")
            if next_url and next_url.startswith("/"):
                return redirect(next_url)
            return redirect(url_for("admin"))
        else:
            flash("Username atau kata sandi salah. Akses ditolak.", "error")

    return render_template("login.html", data=data, active_page="login")


@app.route("/logout")
def logout():
    session.clear()
    flash("Anda telah keluar dari sesi pengelola.", "success")
    return redirect(url_for("index"))


@app.route("/admin", methods=["GET", "POST"])
@login_required
def admin():
    data = load_data()
    auth = load_auth()

    if request.method == "POST":
        section = request.form.get("section")

        if section == "security":
            current_pw = request.form.get("current_password", "")
            new_username = request.form.get("new_username", "").strip()
            new_pw = request.form.get("new_password", "")
            confirm_pw = request.form.get("confirm_password", "")

            if not check_password_hash(auth.get("password_hash", ""), current_pw):
                flash("Kata sandi saat ini tidak sesuai.", "error")
                return redirect(url_for("admin"))

            if not new_username:
                flash("Username tidak boleh kosong.", "error")
                return redirect(url_for("admin"))

            auth["username"] = new_username
            if new_pw:
                if len(new_pw) < 6:
                    flash("Kata sandi baru minimal 6 karakter.", "error")
                    return redirect(url_for("admin"))
                if new_pw != confirm_pw:
                    flash("Konfirmasi kata sandi baru tidak cocok.", "error")
                    return redirect(url_for("admin"))
                auth["password_hash"] = generate_password_hash(new_pw)

            save_auth(auth)
            session["admin_user"] = new_username
            flash("Kredensial login pengelola berhasil diperbarui!", "success")

        elif section == "profile":
            data["profile"]["name"] = request.form.get("name", data["profile"]["name"]).strip()
            data["profile"]["role"] = request.form.get("role", data["profile"]["role"]).strip()
            data["profile"]["tagline"] = request.form.get("tagline", data["profile"]["tagline"]).strip()
            data["profile"]["bio"] = request.form.get("bio", data["profile"]["bio"]).strip()
            data["profile"]["availability"] = request.form.get("availability", data["profile"]["availability"]).strip()
            data["profile"]["avatar"] = request.form.get("avatar", data["profile"]["avatar"]).strip()
            data["profile"]["email"] = request.form.get("email", data["profile"]["email"]).strip()
            data["profile"]["phone"] = request.form.get("phone", data["profile"]["phone"]).strip()
            data["profile"]["location"] = request.form.get("location", data["profile"]["location"]).strip()
            save_data(data)
            flash("Profil utama berhasil diperbarui!", "success")

        elif section == "biodata":
            labels = request.form.getlist("bio_label[]")
            values = request.form.getlist("bio_value[]")
            new_biodata = []
            for lbl, val in zip(labels, values):
                if lbl.strip() and val.strip():
                    new_biodata.append({"label": lbl.strip(), "value": val.strip()})
            data["biodata"] = new_biodata
            save_data(data)
            flash("Informasi umum & biodata berhasil diperbarui!", "success")

        elif section == "education":
            periods = request.form.getlist("edu_period[]")
            institutions = request.form.getlist("edu_institution[]")
            degrees = request.form.getlist("edu_degree[]")
            gpas = request.form.getlist("edu_gpa[]")
            descriptions = request.form.getlist("edu_description[]")
            new_edu = []
            for p, inst, deg, gpa, desc in zip(periods, institutions, degrees, gpas, descriptions):
                if inst.strip() and deg.strip():
                    new_edu.append({
                        "period": p.strip(),
                        "institution": inst.strip(),
                        "degree": deg.strip(),
                        "gpa": gpa.strip(),
                        "description": desc.strip()
                    })
            data["education"] = new_edu
            save_data(data)
            flash("Riwayat pendidikan berhasil diperbarui!", "success")

        elif section == "projects":
            titles = request.form.getlist("proj_title[]")
            categories = request.form.getlist("proj_category[]")
            years = request.form.getlist("proj_year[]")
            images = request.form.getlist("proj_image[]")
            summaries = request.form.getlist("proj_summary[]")
            tags_list = request.form.getlist("proj_tags[]")
            links = request.form.getlist("proj_link[]")
            new_projects = []
            for idx, (t, c, y, img, s, tg, lnk) in enumerate(zip(titles, categories, years, images, summaries, tags_list, links), start=1):
                if t.strip():
                    new_projects.append({
                        "id": f"proj-{idx}",
                        "title": t.strip(),
                        "category": c.strip(),
                        "year": y.strip(),
                        "image": img.strip() or "/static/images/project-1.svg",
                        "summary": s.strip(),
                        "tags": [tag.strip() for tag in tg.split(",") if tag.strip()],
                        "link": lnk.strip() or "#"
                    })
            data["projects"] = new_projects
            save_data(data)
            flash("Daftar proyek berhasil diperbarui!", "success")

        return redirect(url_for("admin"))

    return render_template("admin.html", data=data, auth=auth, active_page="admin")


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
