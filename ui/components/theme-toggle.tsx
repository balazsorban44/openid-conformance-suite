"use client";

import { Monitor, Moon, Sun } from "lucide-react";
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { Button } from "@/components/ui/button.tsx";
import {
	DropdownMenu,
	DropdownMenuContent,
	DropdownMenuRadioGroup,
	DropdownMenuRadioItem,
	DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu.tsx";
import { THEME_STORAGE_KEY as STORAGE_KEY } from "@/lib/theme-script.ts";

export type Theme = "light" | "dark" | "system";

const ThemeContext = createContext<{ theme: Theme; resolved: "light" | "dark"; setTheme: (t: Theme) => void }>({
	theme: "system",
	resolved: "light",
	setTheme: () => {},
});

export function useTheme() {
	return useContext(ThemeContext);
}

/** Light, dark or the system's: the `dark` class on <html>, remembered in localStorage */
export function ThemeProvider({ children }: { children: React.ReactNode }) {
	const [theme, setThemeState] = useState<Theme>("system");
	const [systemDark, setSystemDark] = useState(false);
	useEffect(() => {
		try {
			const stored = localStorage.getItem(STORAGE_KEY);
			if (stored === "light" || stored === "dark" || stored === "system") {
				setThemeState(stored);
			}
		} catch {
			// storage unavailable: follow the system
		}
		const media = matchMedia("(prefers-color-scheme: dark)");
		setSystemDark(media.matches);
		const onChange = (e: MediaQueryListEvent) => setSystemDark(e.matches);
		media.addEventListener("change", onChange);
		return () => media.removeEventListener("change", onChange);
	}, []);
	const resolved = theme === "system" ? (systemDark ? "dark" : "light") : theme;
	useEffect(() => {
		document.documentElement.classList.toggle("dark", resolved === "dark");
		document.documentElement.style.colorScheme = resolved;
	}, [resolved]);
	const setTheme = useCallback((t: Theme) => {
		setThemeState(t);
		try {
			localStorage.setItem(STORAGE_KEY, t);
		} catch {
			// not remembered
		}
	}, []);
	const value = useMemo(() => ({ theme, resolved, setTheme }), [theme, resolved, setTheme]);
	return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function ThemeToggle() {
	const { theme, setTheme } = useTheme();
	return (
		<DropdownMenu>
			<DropdownMenuTrigger asChild>
				<Button variant="ghost" size="icon" className="size-8" aria-label="Theme">
					<Sun className="size-4 scale-100 rotate-0 transition-all dark:scale-0 dark:-rotate-90" />
					<Moon className="absolute size-4 scale-0 rotate-90 transition-all dark:scale-100 dark:rotate-0" />
				</Button>
			</DropdownMenuTrigger>
			<DropdownMenuContent align="end">
				<DropdownMenuRadioGroup value={theme} onValueChange={(v) => setTheme(v as Theme)}>
					<DropdownMenuRadioItem value="light">
						<Sun /> Light
					</DropdownMenuRadioItem>
					<DropdownMenuRadioItem value="dark">
						<Moon /> Dark
					</DropdownMenuRadioItem>
					<DropdownMenuRadioItem value="system">
						<Monitor /> System
					</DropdownMenuRadioItem>
				</DropdownMenuRadioGroup>
			</DropdownMenuContent>
		</DropdownMenu>
	);
}
