// Adapted from Starlight 0.42.6 (MIT); see STARLIGHT-LICENSE.
import { headingLinkIconChildren } from './markdown-icon.mjs';
function satteriRtlCodeSupportPlugin() {
	return {
		name: "starlight-rtl-code-support",
		element: [{
			filter: ["pre"],
			visit(node, ctx) {
				if (node.properties && "dir" in node.properties) return;
				ctx.setProperty(node, "dir", "ltr");
			}
		}, {
			filter: ["code"],
			visit(node, ctx) {
				if (!(node.properties && "dir" in node.properties) && !hasPreParent(node, ctx)) ctx.setProperty(node, "dir", "auto");
			}
		}]
	};
}
/**
* Check if any parent of `child` is a `<pre>` element by walking up the tree.
*/
function hasPreParent(child, ctx) {
	while (child) {
		const parent = ctx.parent(child);
		if (parent?.type === "element" && parent.tagName === "pre") return true;
		child = parent;
	}
	return false;
}
function satteriAutolinkHeadingsPlugin(t) {
	return {
		name: "starlight-autolink-headings",
		element: {
			filter: [
				"h1",
				"h2",
				"h3",
				"h4",
				"h5",
				"h6"
			],
			visit(node, ctx) {
				const id = node.properties?.["id"];
				if (typeof id !== "string" || !id) return;
				const accessibleLabel = t("heading.anchorLabel", {
					title: ctx.textContent(node),
					interpolation: { escapeValue: false }
				});
				return {
					type: "element",
					tagName: "div",
					properties: { class: `sl-heading-wrapper level-${node.tagName}` },
					children: [node, {
						type: "element",
						tagName: "a",
						properties: {
							class: "sl-anchor-link",
							href: "#" + id
						},
						children: [{
							type: "element",
							tagName: "span",
							properties: {
								"aria-hidden": "true",
								class: "sl-anchor-icon"
							},
							children: [{
								type: "element",
								tagName: "svg",
								properties: {
									width: "16",
									height: "16",
									viewBox: "0 0 24 24",
									fill: "currentColor"
								},
								children: headingLinkIconChildren
							}]
						}, {
							type: "element",
							tagName: "span",
							properties: {
								class: "sr-only",
								"data-pagefind-ignore": true
							},
							children: [{
								type: "text",
								value: accessibleLabel
							}]
						}]
					}]
				};
			}
		}
	};
}

export { satteriRtlCodeSupportPlugin, satteriAutolinkHeadingsPlugin };
