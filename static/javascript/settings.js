let settings = document.getElementById("settings");
let username = document.getElementById("username");
let password = document.getElementById("password");
let email = document.getElementById("email");
let show_email = document.getElementById("show_email");
let cookies = document.cookie.split("; ")
document.addEventListener('DOMContentLoaded', () => {
    let cookie = ""
    cookies.forEach(value => {
        if (value.startsWith("GAUTH-JWT=")) {
            cookie = value.substring(10)
        }
    })
    if (cookie === "") {
        window.location.href = "/login";
    }
    let url = "/validate";
    let options = {
        method: "POST",
        body: cookie,
    }
    fetch(url, options).then(async r => {
        if (!r.ok) {
            if (r.status === 404) {
                window.location.href = "/login";
            } else {
                console.error("CODE " + r.status + ": " + r.statusText);
            }
            return;
        }
        let data = r.text();
        let claims = JSON.parse(await data);
        if (!claims["authorized"] || claims.User.uuid !== givenUUID) {
            window.location.href = "/login";
        }
        settings.removeAttribute("hidden")
    });
});

function saveSettings() {
    let cookie = ""
    cookies.forEach(value => {
        if (value.startsWith("GAUTH-JWT=")) {
            cookie = value.substring(10)
        }
    });
    let url = "/validate";
    let options = {
        method: "POST",
        body: cookie,
    }
    fetch(url, options).then(async r => {
        if (!r.ok) {
            if (r.status === 404) {
                loginButton.removeAttribute("hidden");
            } else {
                console.error("CODE " + r.status + ": " + r.statusText);
            }
            return;
        }
        let data = await r.text();
        let claims = JSON.parse(data);
        if (claims["authorized"]) {
            if (claims.User.uuid === givenUUID) {
                let user = {
                    "uuid": claims.User.uuid,
                    "username": username.value,
                    "email": email.value,
                    "password": password.value,
                    "show_email": show_email.checked,
                }
                url = "settings"
                options = {
                    method: "POST",
                    body: JSON.stringify(user)
                }
                fetch(url, options).then(async r => {
                    if (!r.ok) {
                        if (r.status === 404) {
                            loginButton.removeAttribute("hidden");
                        } else {
                            console.error("CODE " + r.status + ": " + r.statusText);
                        }
                        return;
                    }
                    window.location.href = "/";
                })
            }
        }
    });
}