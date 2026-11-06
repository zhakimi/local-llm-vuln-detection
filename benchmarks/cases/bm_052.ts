export function renderGreeting(): void {
  const params = new URLSearchParams(window.location.search);
  const name = params.get("name") ?? "friend";
  const banner = document.getElementById("banner") as HTMLDivElement;
  const strong = document.createElement("strong");
  strong.textContent = `Hello, ${name}`;
  banner.replaceChildren(strong);
}

document.addEventListener("DOMContentLoaded", renderGreeting);
