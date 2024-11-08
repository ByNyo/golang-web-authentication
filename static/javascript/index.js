document.addEventListener('DOMContentLoaded', (event) => {
    event.preventDefault();
    let loginButton = document.getElementById("login");
    let profileButton = document.getElementById("profile");
    let cookies = document.cookie.split("; ")
    let cookie = ""
    cookies.forEach(value => {
        if (value.startsWith("GAUTH-JWT=")) {
            cookie = value.substring(10)
        }
    })
    if (cookie === "") {
        profileButton.outerHTML = "";
        loginButton.removeAttribute("hidden");
        return;
    }
    let url = "/validate";
    let options = {
        method: "POST",
        body: cookie,
    }
    fetch(url, options).then(r => {
        if (!r.ok) {
            if (r.status === 404) {
                profileButton.outerHTML = "";
                loginButton.removeAttribute("hidden");
            } else {
                console.error("CODE " + r.status + ": " + r.statusText);
            }
            return;
        }
        loginButton.outerHTML = "";
        profileButton.removeAttribute("hidden");
    });
});

function profile(username) {
    window.location.href = "/profile/@" + username;
}