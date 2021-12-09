let eyeIcon1 = document.querySelector(".form-group i.pass1");
let eyeIcon2 = document.querySelector(".form-group .pass2");
// let inputs = document.querySelectorAll("input[type='password']");
let password = document.querySelector("#password")
let password2 = document.querySelector("#confirm-password");
// console.log(inputs);

eyeIcon1.onclick = function() {
    if (password.type === "password") {
        password.type = "text";
        eyeIcon1.className = "fa fa-eye-slash";
    } else {
        password.type = "password";
        eyeIcon1.className = "fa fa-eye";
    }
}

eyeIcon2.onclick = function() {
    if (password2.type === "password") {
        password2.type = "text";
        eyeIcon2.className = "fa fa-eye-slash";
    } else {
        password2.type = "password";
        eyeIcon2.className = "fa fa-eye";
    }
}