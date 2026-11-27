from flask import Flask
from routes.scan_routes import scan_bp
from database.db import init_db

app = Flask(
    __name__,
    static_folder="../frontend",
    static_url_path=""
)

# Initialize SQLite database
init_db()

app.register_blueprint(scan_bp)


@app.route("/")
def home():
    return app.send_static_file("index.html")


if __name__ == "__main__":
    app.run(debug=True)