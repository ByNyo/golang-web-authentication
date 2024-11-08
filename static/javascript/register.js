document.addEventListener('keyup', () => {
    checkPasswords();
})
let pw = document.getElementById("Password").value;
let pwc = document.getElementById("PasswordCheck").value;
function checkPasswords() {
    let pwm = document.getElementById("pwmatch");
    if (pw != null && pwc != null) {
        if (pw !== pwc) {
            pwm.removeAttribute("hidden")
        } else {
            pwm.setAttribute("hidden", "true")
        }
    }
}
function validatePasswords() {
    if (pw === null || pwc === null) {
        return false
    }
    return !(pw.value === "" || pwc.value === "");
}

function showPassword(isSecond) {
    let pw = document.getElementById("Password")
    if (isSecond) {
        pw = document.getElementById("PasswordCheck")
    }
    let t = pw.getAttribute("type")
    if (t === "password") {
        pw.setAttribute("type", "text")
    } else {
        pw.setAttribute("type", "password")
    }
}

function signup() {
    if (validatePasswords()) {
        let username = document.getElementById("Username").value;
        let pw = document.getElementById("Password").value;
        let email = document.getElementById("EMail").value;
        if (email == null) {
            email = ""
        }
        let user = {
            "username": username,
            "password": pw,
            "email": email,
        }
        let options = {
            method: "POST",
            body: JSON.stringify(user),
        }
        fetch("/register", options).then(r => {
            if (!r.ok) {
                console.error("CODE " + r.status + ": " + r.statusText)
            }
            if (r.redirected) {
                window.location.href = r.url
            }
        }).catch(error => {
            console.log(error)
        })
    }
}