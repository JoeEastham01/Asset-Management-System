document.addEventListener("DOMContentLoaded", function () {
    const inputs = document.querySelectorAll('.track-change');
    const saveButton = document.getElementById('save-button');
    const originalValues = {};

    inputs.forEach(input => {
        originalValues[input.name] = input.value;

        input.addEventListener('input', () => {
            let changed = false;
            for (let inp of inputs) {
                if (inp.value !== originalValues[inp.name]) {
                    changed = true;
                    break;
                }
            }
            saveButton.style.display = changed ? 'inline-block' : 'none';
        });
    });
});
