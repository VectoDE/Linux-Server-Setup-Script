// SPDX-FileCopyrightText: 2025-2026 VectoDE
//
// SPDX-License-Identifier: MIT

// Plays the film. Scrolling through a scene moves its progress from 0 to 1, and the progress decides which lines are
// shown (steps), how far the stage has rolled (roll), which item is current (switch) and how far the opening has
// stepped back (hero). Behind the text a field of packets drifts across the screen and closes into a shield while the
// module groups pass. Every word is in the page from the start; this script only moves and marks it. With reduced
// motion, without scripting or on a short screen the stylesheet shows the scenes as a still sequence, and the script
// only keeps the scene counter up to date.
"use strict";

(() => {
	const film = globalThis.matchMedia(
		"(prefers-reduced-motion: no-preference) and (scripting: enabled) and (height >= 30rem)",
	);
	const dark = globalThis.matchMedia("(prefers-color-scheme: dark)");
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
		cap: element.querySelector(".cap"),
		steps: Array.from(element.querySelectorAll(".s")),
		items: Array.from(element.querySelectorAll(".m")),
		lists: Array.from(element.querySelectorAll("[data-switch]"), (list) => Array.from(list.children)),
		shift: -1,
		split: false,
		vars: "",
	}));
	const groups = scenes.filter((scene) => scene.element.id.startsWith("group-"));
	const marks = {
		start: document.getElementById("run"),
		end: groups.length > 0 ? groups.at(-1).element : null,
		guard: document.getElementById("guard"),
	};
	// What the field needs from the page, written by render() on scroll and read by the field on every frame.
	const state = { condense: 0, fade: 1, scan: -1, ghost: "", drift: 0 };
	let queued = false;
	let shown = -1;

	const clamp = (value) => Math.min(1, Math.max(0, value));
	const easeOut = (value) => 1 - (1 - value) ** 3;

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
		if (scene.kind === "hero") {
			return;
		}
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

	// The words of a caption, each in a span of its own with its place in the caption (--i, 0 to 1). Only text nodes
	// are split, so links and code stay what they are.
	function splitCaption(scene) {
		scene.split = true;
		if (!scene.cap || scene.kind === "hero") {
			return;
		}
		const walker = document.createTreeWalker(scene.cap, NodeFilter.SHOW_TEXT);
		const texts = [];
		while (walker.nextNode()) {
			texts.push(walker.currentNode);
		}
		const words = [];
		for (const text of texts) {
			const part = document.createDocumentFragment();
			for (const piece of text.data.split(/(\s+)/)) {
				if (piece.trim() === "") {
					part.append(piece);
				} else {
					const word = document.createElement("span");
					word.className = "wd";
					word.textContent = piece;
					words.push(word);
					part.append(word);
				}
			}
			text.replaceWith(part);
		}
		for (const [index, word] of words.entries()) {
			word.style.setProperty("--i", (index / Math.max(1, words.length - 1)).toFixed(3));
		}
	}

	// --p (progress of a played scene) and --r (how far the scene has come in, for its caption) are only set while the
	// scene is on the screen. Without them the stylesheet shows everything as it is.
	function setVars(scene, progress, arrival) {
		const value = `${progress.toFixed(3)} ${arrival.toFixed(3)}`;
		if (value === scene.vars) {
			return;
		}
		scene.vars = value;
		scene.element.style.setProperty("--p", progress.toFixed(3));
		scene.element.style.setProperty("--r", arrival.toFixed(3));
	}

	function clearVars(scene) {
		if (scene.vars !== "") {
			scene.vars = "";
			scene.element.style.removeProperty("--p");
			scene.element.style.removeProperty("--r");
		}
	}

	function still() {
		for (const scene of scenes) {
			roll(scene, 0);
			clearVars(scene);
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

	function updateScene(scene, box, height) {
		if (!film.matches || box.bottom <= 0 || box.top >= height) {
			clearVars(scene);
			return;
		}
		if (!scene.split) {
			splitCaption(scene);
		}
		const run = box.height - height;
		const progress = scene.played && run > 0 ? clamp(-box.top / run) : 0;
		if (scene.played && run > 0) {
			play(scene, progress);
		}
		setVars(scene, progress, clamp((height - box.top) / (1.6 * height)));
	}

	// The shield closes from the moment the first run is half up the screen to the end of the last module group; the
	// guard sweeps a scan line over it; after the guard the field fades out.
	function updateField(height, current) {
		if (marks.start && marks.end) {
			const start = marks.start.getBoundingClientRect().top;
			const span = marks.end.getBoundingClientRect().bottom - start - height / 2;
			state.condense = clamp((height / 2 - start) / span);
		}
		if (marks.guard) {
			const box = marks.guard.getBoundingClientRect();
			state.fade = clamp(box.bottom / height);
			const run = box.height - height;
			state.scan = box.top <= 0 && box.bottom >= height && run > 0 ? clamp(-box.top / run) : -1;
		}
		state.ghost = scenes[current].element.dataset.title;
		state.drift = globalThis.scrollY;
	}

	// All boxes are measured first and only then written to, so a frame lays the page out once (the rolls of the
	// one or two scenes on the screen measure their own stage, which the writes before them leave in place).
	function render() {
		queued = false;
		const height = globalThis.innerHeight;
		const total = document.documentElement.scrollHeight - height;
		const boxes = scenes.map((scene) => scene.element.getBoundingClientRect());
		let current = 0;
		for (const [index, box] of boxes.entries()) {
			if (box.top <= height / 2) {
				current = index;
			}
		}
		updateField(height, current);
		for (const [index, scene] of scenes.entries()) {
			updateScene(scene, boxes[index], height);
		}
		updateCounter(current);
		field.wake();
		bar.style.transform = `scaleX(${total > 0 ? clamp(globalThis.scrollY / total) : 0})`;
	}

	function queue() {
		if (!queued) {
			queued = true;
			globalThis.requestAnimationFrame(render);
		}
	}

	// The field. Each packet has a place on the screen it drifts from and a place in the shield it closes into; the
	// order in which they arrive is random, so the shape fills in rather than wiping across.
	const field = (() => {
		const canvas = document.querySelector(".field");
		const context = canvas ? canvas.getContext("2d", { alpha: true }) : null;
		const colours = { ink: "", muted: "", mark: "", mono: "" };
		let packets = null;
		let width = 0;
		let height = 0;
		let running = false;
		let started = false;
		let smooth = 0;
		let blank = false;

		function readColours() {
			const style = getComputedStyle(document.documentElement);
			for (const name of ["ink", "muted", "mark", "mono"]) {
				colours[name] = style.getPropertyValue(`--${name}`).trim();
			}
		}

		// Points of a shield with "lss" cut out of it, from a small drawing that is read once. The grid is as fine as the
		// number of packets allows, so that every point gets one and the letters stay readable.
		function shieldPoints(count) {
			const sketch = document.createElement("canvas");
			sketch.width = 200;
			sketch.height = 240;
			const pen = sketch.getContext("2d", { willReadFrequently: true });
			pen.beginPath();
			pen.moveTo(100, 4);
			pen.lineTo(196, 34);
			pen.lineTo(196, 112);
			pen.quadraticCurveTo(196, 196, 100, 236);
			pen.quadraticCurveTo(4, 196, 4, 112);
			pen.lineTo(4, 34);
			pen.closePath();
			pen.fill();
			pen.globalCompositeOperation = "destination-out";
			pen.font = `800 76px ${colours.mono}`;
			pen.textAlign = "center";
			pen.fillText("lss", 100, 140);
			const pixels = pen.getImageData(0, 0, 200, 240).data;
			let area = 0;
			for (let index = 3; index < pixels.length; index += 4) {
				area += pixels[index] > 128 ? 1 : 0;
			}
			return sample(pixels, Math.max(2, Math.sqrt(area / count) * 1.02));
		}

		function sample(pixels, step) {
			const points = [];
			for (let y = step / 2; y < 240; y += step) {
				for (let x = step / 2; x < 200; x += step) {
					if (pixels[(Math.floor(y) * 200 + Math.floor(x)) * 4 + 3] > 128) {
						points.push((x - 100) / 240, (y - 120) / 240);
					}
				}
			}
			return points;
		}

		// The scatter of the packets only has to look random, and the same on every visit: a small seeded generator
		// (mulberry32), nothing that needs to be unpredictable.
		let seed = 0x6c7373;
		function scatter() {
			seed = (seed + 0x6d2b79f5) | 0;
			let value = Math.imul(seed ^ (seed >>> 15), 1 | seed);
			value = (value + Math.imul(value ^ (value >>> 7), 61 | value)) ^ value;
			return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
		}

		function makePackets() {
			seed = 0x6c7373;
			const count = Math.round(Math.min(2200, Math.max(500, (width * height) / 420)));
			const points = shieldPoints(count);
			const total = points.length / 2;
			const order = Array.from({ length: total }, (_, index) => index);
			for (let index = total - 1; index > 0; index -= 1) {
				const other = Math.floor(scatter() * (index + 1));
				[order[index], order[other]] = [order[other], order[index]];
			}
			packets = Array.from({ length: count }, (_, index) => {
				const point = order[index % total];
				const spread = index < total ? 0 : 0.006;
				return {
					hx: scatter(),
					hy: scatter(),
					speed: 0.00001 + scatter() * 0.00003,
					depth: 0.3 + scatter() * 0.7,
					tx: points[point * 2] + (scatter() - 0.5) * spread,
					ty: points[point * 2 + 1] + (scatter() - 0.5) * spread,
					delay: scatter(),
				};
			});
		}

		function resize() {
			const ratio = Math.min(1.5, globalThis.devicePixelRatio || 1);
			width = globalThis.innerWidth;
			height = globalThis.innerHeight;
			canvas.width = Math.round(width * ratio);
			canvas.height = Math.round(height * ratio);
			context.setTransform(ratio, 0, 0, ratio, 0, 0);
		}

		function drawGhost() {
			if (shown <= 0) {
				return;
			}
			const size = Math.round(Math.min(height * 0.3, width * 0.22));
			context.font = `800 ${size}px ${colours.mono}`;
			context.fillStyle = colours.ink;
			context.globalAlpha = 0.05;
			context.fillText(state.ghost, -state.drift * 0.08 % width, height * 0.62);
		}

		// One frame: packets drift on their own line until their turn comes, then travel into the shield.
		function draw(time) {
			context.clearRect(0, 0, width, height);
			context.globalAlpha = 1;
			drawGhost();
			smooth += (state.condense - smooth) * 0.08;
			const size = Math.min(width * (width >= 900 ? 0.42 : 0.78), height * 0.62) * 1.2;
			const centreX = width >= 900 ? width * 0.7 : width / 2;
			const centreY = height * 0.54;
			const scanY = state.scan >= 0 ? centreY + (state.scan - 0.5) * size : -1e4;
			const buckets = [[], [], []];
			for (const packet of packets) {
				const turn = easeOut(clamp((smooth - packet.delay * 0.6) / 0.4));
				const freeX = ((packet.hx + time * packet.speed) % 1) * width;
				const freeY = packet.hy * height - state.drift * 0.04 * packet.depth;
				const y = ((freeY % height) + height) % height;
				const x = freeX + (centreX + packet.tx * size - freeX) * turn;
				const ty = y + (centreY + packet.ty * size - y) * turn;
				let bucket = turn >= 1 ? 1 : 0;
				if ((turn > 0 && turn < 1) || Math.abs(ty - scanY) < 6) {
					bucket = 2;
				}
				buckets[bucket].push(x, ty);
			}
			// On a narrow screen the shield sits behind the text, so it is drawn fainter there.
			const level = state.fade * (width >= 900 ? 1 : 0.5);
			paint(buckets[0], colours.muted, 0.34 * level);
			paint(buckets[1], colours.ink, 0.42 * level);
			paint(buckets[2], colours.mark, 0.7 * level);
			if (state.scan >= 0) {
				context.fillStyle = colours.mark;
				context.globalAlpha = level;
				context.fillRect(centreX - size * 0.45, scanY - 1, size * 0.9, 2);
			}
		}

		function paint(points, colour, alpha) {
			context.fillStyle = colour;
			context.globalAlpha = alpha;
			for (let index = 0; index < points.length; index += 2) {
				context.fillRect(points[index], points[index + 1], 2, 2);
			}
		}

		function frame(time) {
			if (!running) {
				return;
			}
			if (state.fade <= 0) {
				// Past the guard: one empty frame, then nothing until the field comes back into play.
				if (!blank) {
					context.clearRect(0, 0, width, height);
					blank = true;
				}
				running = false;
				return;
			}
			blank = false;
			draw(time);
			globalThis.requestAnimationFrame(frame);
		}

		function wake() {
			if (!started || running || document.hidden || !film.matches || state.fade <= 0) {
				return;
			}
			running = true;
			globalThis.requestAnimationFrame(frame);
		}

		function sleep() {
			running = false;
		}

		function start() {
			if (!context || started || !film.matches) {
				return;
			}
			started = true;
			readColours();
			resize();
			makePackets();
			wake();
		}

		function refit() {
			if (started) {
				resize();
			}
		}

		function recolour() {
			if (started) {
				readColours();
			}
		}

		return { start, wake, sleep, refit, recolour };
	})();

	// The numbers of the opening count up once, from 0 to what the repository holds.
	function countUp() {
		const numbers = Array.from(document.querySelectorAll("dd[data-count]"), (element) => ({
			element,
			target: Number(element.dataset.count),
		}));
		// Each number keeps the width of its final value, so counting does not move the labels around it.
		for (const number of numbers) {
			number.element.style.minWidth = `${String(number.target).length}ch`;
		}
		const begin = performance.now();
		const tick = (time) => {
			const done = clamp((time - begin) / 1400);
			for (const number of numbers) {
				number.element.textContent = String(Math.round(easeOut(done) * number.target));
			}
			if (done < 1) {
				globalThis.requestAnimationFrame(tick);
			}
		};
		globalThis.requestAnimationFrame(tick);
	}

	// Where the browser cannot drive the heading masks by scroll, they rise once their heading comes into view. The
	// stylesheet only lowers them once this script has marked the page (fx), so a page whose script did not load
	// keeps its headings in place.
	function watchHeadings() {
		if (globalThis.CSS?.supports("animation-timeline: view()") || !("IntersectionObserver" in globalThis)) {
			return;
		}
		document.documentElement.classList.add("fx");
		const observer = new IntersectionObserver(
			(entries) => {
				for (const entry of entries) {
					if (entry.isIntersecting) {
						entry.target.classList.add("seen");
						observer.unobserve(entry.target);
					}
				}
			},
			{ threshold: 0.2 },
		);
		for (const heading of document.querySelectorAll("h2")) {
			observer.observe(heading);
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
		if (film.matches) {
			field.start();
		} else {
			field.sleep();
			still();
		}
		queue();
	});
	dark.addEventListener("change", field.recolour);
	document.addEventListener("visibilitychange", () => {
		if (document.hidden) {
			field.sleep();
		} else {
			field.wake();
		}
	});
	globalThis.addEventListener("scroll", queue, { passive: true });
	globalThis.addEventListener(
		"resize",
		() => {
			field.refit();
			queue();
		},
		{ passive: true },
	);

	// The first frame waits for the page to load: by then the browser has laid it out, so measuring the scenes costs
	// nothing, and the page is complete without this frame anyway. The field and the counters start after it.
	function begin() {
		watchHeadings();
		queue();
		if (film.matches) {
			countUp();
			const later = globalThis.requestIdleCallback?.bind(globalThis) ?? ((callback) => globalThis.setTimeout(callback, 600));
			later(
				() => {
					field.start();
					queue();
				},
				{ timeout: 1500 },
			);
		}
	}

	if (document.readyState === "complete") {
		begin();
	} else {
		globalThis.addEventListener("load", begin, { once: true });
	}
})();
