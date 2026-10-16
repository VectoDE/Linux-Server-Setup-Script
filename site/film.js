// SPDX-FileCopyrightText: 2025-2026 VectoDE
//
// SPDX-License-Identifier: MIT

// Plays the film. Scrolling through a scene moves its progress from 0 to 1, and the progress decides which lines are
// shown (steps), how far the stage has rolled (roll) and which item is current (switch). Every word is in the page
// from the start; this script only moves and marks it. With reduced motion, without scripting or on a short screen
// the stylesheet shows the scenes as a still sequence and the script only keeps the scene counter up to date.
"use strict";

(() => {
	const film = globalThis.matchMedia(
		"(prefers-reduced-motion: no-preference) and (scripting: enabled) and (height >= 30rem)",
	);
	const counter = document.getElementById("tc-n");
	const title = document.getElementById("tc-title");
	const bar = document.querySelector(".bar");
	const scenes = Array.from(document.querySelectorAll(".scene"), (element) => ({
		element,
		kind: element.dataset.kind,
		// A scene of one screen (l1) is not played; it scrolls past like a page.
		played: !element.classList.contains("l1"),
		win: element.querySelector(".win"),
		stage: element.querySelector(".stage"),
		steps: Array.from(element.querySelectorAll(".s")),
		items: Array.from(element.querySelectorAll(".m")),
		lists: Array.from(element.querySelectorAll("[data-switch]"), (list) => Array.from(list.children)),
		shift: -1,
	}));
	let queued = false;
	let shown = -1;

	const clamp = (value) => Math.min(1, Math.max(0, value));

	// Bottom edge of an element, measured from the top of the stage, which is what a roll has to bring into view.
	const bottomIn = (stage, element) =>
		element.getBoundingClientRect().bottom - stage.getBoundingClientRect().top;

	function roll(scene, shift) {
		const value = Math.round(Math.max(0, shift));
		if (value !== scene.shift) {
			scene.shift = value;
			scene.stage.style.transform = value ? `translate3d(0, ${-value}px, 0)` : "";
		}
	}

	// Lines appear one by one over the first 85 % of the scene, the newest is marked, and the stage rolls like a
	// terminal once they no longer fit.
	function playSteps(scene, progress) {
		const count = scene.steps.length;
		const visible = Math.max(1, Math.min(count, Math.ceil((progress / 0.85) * count)));
		for (const [index, step] of scene.steps.entries()) {
			step.classList.toggle("on", index < visible);
			step.classList.toggle("now", index === visible - 1 && progress < 1);
		}
		roll(scene, bottomIn(scene.stage, scene.steps[visible - 1]) - scene.win.clientHeight);
	}

	function playRoll(scene, progress) {
		const count = scene.items.length;
		const current = Math.round(progress * (count - 1));
		for (const [index, item] of scene.items.entries()) {
			item.classList.toggle("cur", index === current);
		}
		roll(scene, progress * (scene.stage.scrollHeight - scene.win.clientHeight));
	}

	// One item per equal part of the scene; within its part, a tall item rolls to its end.
	function playSwitch(scene, progress) {
		const count = scene.lists[0].length;
		const current = Math.min(count - 1, Math.floor(progress * count));
		for (const list of scene.lists) {
			for (const [index, item] of list.entries()) {
				item.classList.toggle("on", index === current);
			}
		}
		const active = scene.lists.at(-1)[current];
		const local = clamp(progress * count - current);
		roll(scene, local * (bottomIn(scene.stage, active) - scene.win.clientHeight));
	}

	function play(scene, progress) {
		if (scene.kind === "steps" && scene.steps.length > 0) {
			playSteps(scene, progress);
		} else if (scene.kind === "roll" && scene.items.length > 0) {
			playRoll(scene, progress);
		} else if (scene.kind === "switch" && scene.lists.length > 0) {
			playSwitch(scene, progress);
		} else {
			roll(scene, progress * (scene.stage.scrollHeight - scene.win.clientHeight));
		}
	}

	function still() {
		for (const scene of scenes) {
			roll(scene, 0);
		}
	}

	function updateCounter(index) {
		if (index === shown) {
			return;
		}
		shown = index;
		counter.textContent = String(index + 1).padStart(2, "0");
		title.textContent = scenes[index].element.dataset.title;
	}

	function render() {
		queued = false;
		const height = globalThis.innerHeight;
		let current = 0;
		for (const [index, scene] of scenes.entries()) {
			const box = scene.element.getBoundingClientRect();
			if (box.top <= height / 2) {
				current = index;
			}
			const run = box.height - height;
			if (film.matches && scene.played && run > 0 && box.bottom > 0 && box.top < height) {
				play(scene, clamp(-box.top / run));
			}
		}
		updateCounter(current);
		const total = document.documentElement.scrollHeight - height;
		bar.style.transform = `scaleX(${total > 0 ? clamp(globalThis.scrollY / total) : 0})`;
	}

	function queue() {
		if (!queued) {
			queued = true;
			globalThis.requestAnimationFrame(render);
		}
	}

	// The chapter list closes when a chapter is chosen, and with Escape, which returns focus to its button.
	const chapters = document.querySelector(".hud-nav details");
	chapters.addEventListener("click", (event) => {
		if (event.target.closest("a")) {
			chapters.open = false;
		}
	});
	document.addEventListener("keydown", (event) => {
		if (event.key === "Escape" && chapters.open) {
			chapters.open = false;
			chapters.querySelector("summary").focus();
		}
	});

	film.addEventListener("change", () => {
		if (!film.matches) {
			still();
		}
		queue();
	});
	globalThis.addEventListener("scroll", queue, { passive: true });
	globalThis.addEventListener("resize", queue, { passive: true });
	// The first frame waits for the page to load: by then the browser has laid it out, so measuring the scenes costs
	// nothing, and the page is complete without this frame anyway.
	if (document.readyState === "complete") {
		queue();
	} else {
		globalThis.addEventListener("load", queue, { once: true });
	}
})();
