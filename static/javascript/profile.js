let email = document.getElementById("email");
let cookies = document.cookie.split("; ")
let settings = document.getElementById("settings");
let loginButton = document.getElementById("login");
document.addEventListener('DOMContentLoaded', () => {
    let cookie = ""
    cookies.forEach(value => {
        if (value.startsWith("GAUTH-JWT=")) {
            cookie = value.substring(10)
        }
    })
    if (cookie === "") {
        if (show_email === false) {
            email.outerHTML = "";
            settings.outerHTML = "";
        } else {
            email.removeAttribute("hidden");
        }
        return;
    }
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
        let data = r.text();
        let claims = JSON.parse(await data);
        if (claims["authorized"]) {
            loginButton.outerHTML = "";
        }
        if (claims.User.uuid !== givenUUID) {
            if (show_email === false) {
                email.outerHTML = "";
                settings.outerHTML = "";
            } else {
                email.removeAttribute("hidden");
            }
            return;
        }
        email.removeAttribute("hidden");
        settings.removeAttribute("hidden");
    });
});

function handleSettings() {
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
            loginButton.outerHTML = "";
        }
        if (claims.User.uuid === givenUUID) {
            window.location.href = "/settings";
        }
    });
}