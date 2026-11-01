// Starlight 0.42.6 MIT; see STARLIGHT-LICENSE.
const Icons = {"link-alt": "<path d=\"m12.11 15.39-3.88 3.88a2.52 2.52 0 0 1-3.5 0 2.47 2.47 0 0 1 0-3.5l3.88-3.88a1 1 0 1 0-1.42-1.42l-3.88 3.89a4.48 4.48 0 0 0 6.33 6.33l3.89-3.88a1 1 0 0 0-1.42-1.42m8.58-12.08a4.49 4.49 0 0 0-6.33 0l-3.89 3.88a1 1 0 1 0 1.42 1.42l3.88-3.88a2.52 2.52 0 0 1 3.5 0 2.47 2.47 0 0 1 0 3.5l-3.88 3.88a1 1 0 0 0 0 1.42 1 1 0 0 0 1.42 0l3.88-3.89a4.49 4.49 0 0 0 0-6.33M8.83 15.17a1 1 0 0 0 .71.29 1 1 0 0 0 .71-.29l4.92-4.92a1 1 0 1 0-1.42-1.42l-4.92 4.92a1 1 0 0 0 0 1.42\"/>"};
import { htmlToHast } from "satteri";
//#region src/integrations/markdown-icon.ts
const headingLinkIconSvgChildrenHtml = Icons["link-alt"];
const headingLinkIconChildren = parseIconChildren(headingLinkIconSvgChildrenHtml);
/** Parse a Starlight icon SVG fragment as children of an `<svg>` element. */
function parseIconChildren(icon) {
	return htmlToHast(icon, {
		fragment: true,
		space: "svg"
	}).children;
}
//#endregion
export { headingLinkIconChildren, headingLinkIconSvgChildrenHtml, parseIconChildren };
