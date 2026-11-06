export function renderGreeting(): void {
  const params = new URLSearchParams(window.location.search);
  const name = params.get("name") ?? "friend";
  const banner = document.getElementById("banner") as HTMLDivElement;
  banner.innerHTML = `<strong>Hello, ${name}</strong>`;
}

document.addEventListener("DOMContentLoaded", renderGreeting);
