document.addEventListener("DOMContentLoaded", function () {
    const logoutForms = document.querySelectorAll(".logout-form");

    logoutForms.forEach(form => {
        form.addEventListener("submit", function (e) {
            const confirmed = confirm("Are you sure you want to log out?");
            if (!confirmed) {
                e.preventDefault();
            }
        });
    });
});
