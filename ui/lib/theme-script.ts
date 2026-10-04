export const THEME_STORAGE_KEY = "theme";

/**
 * Sets the `dark` class before the first paint (app/layout.tsx runs it as a beforeInteractive script), from the
 * stored choice (components/theme-toggle.tsx) or the system preference. Not in the client module: a server component
 * importing a constant from a "use client" file gets a client reference, not the string.
 */
export const THEME_SCRIPT = `try{var t=localStorage.getItem("${THEME_STORAGE_KEY}");var d=t==="dark"||((t===null||t==="system")&&matchMedia("(prefers-color-scheme: dark)").matches);document.documentElement.classList.toggle("dark",d);document.documentElement.style.colorScheme=d?"dark":"light"}catch(e){}`;
