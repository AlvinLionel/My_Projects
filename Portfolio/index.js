const menuToggle = document.querySelector(".menu-toggle");
const navigationMenu = document.querySelector(".navigation-menu");
const navigationLinks = document.querySelectorAll(".navigation-menu a");

if (menuToggle && navigationMenu) {
    menuToggle.addEventListener("click", () => {
        const isOpen = navigationMenu.classList.toggle("active");
        menuToggle.setAttribute("aria-expanded", String(isOpen));
    });
}

navigationLinks.forEach((link) => {
    link.addEventListener("click", () => {
        if (!navigationMenu || !menuToggle) return;

        navigationMenu.classList.remove("active");
        menuToggle.setAttribute("aria-expanded", "false");
    });
});

const currentYear = document.querySelector("#current-year");

if (currentYear) currentYear.textContent = new Date().getFullYear();

const placeholderLinks = document.querySelectorAll('a[data-placeholder]');

placeholderLinks.forEach((link) => {
    link.addEventListener("click", (event) => {
        event.preventDefault();
        const placeholderType = link.dataset.placeholder;

        console.info(`Portfolio placeholder clicked: ${placeholderType}`);
    });
});