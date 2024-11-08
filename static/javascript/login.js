function login(event) {
    event.preventDefault();
    let username = document.getElementById("Username").value;
    let password = document.getElementById("Password").value;
    if (username === "") {
        console.error("Username is missing!");
        return
    }
    if (password === "") {
        console.error("Password is missing!");
        return
    }
    let url = "/login?username=" + username + "&password=" + password
    let options = {
        method: "POST"
    }
    fetch(url, options).then(r => {
        if (!r.ok) {
            console.error("CODE " + r.status + ": " + r.statusText);
        }
        if (r.redirected) {
            window.location.href = r.url;
        }
    }).catch(error => {
        if (error != null) {
            console.error(error);
        }
    });
}