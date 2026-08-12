function classifyNode(node) {
  if (!node) {
    return "resource";
  }
  const kind = String(node.kind || "").toLowerCase();
  if (kind.includes("iam")) return "iam";
  if (kind.includes("bucket") || kind.includes("storage")) return "storage";
  if (kind.includes("ec2") || kind.includes("lambda") || kind.includes("compute")) return "compute";
  if (kind === "category") return "category";
  return "resource";
}

function buildGraph(surface) {
  if (!surface || surface.dataset.graphRendered === "true") {
    return;
  }
  const graph = JSON.parse(surface.dataset.graph || "{}");
  const width = surface.clientWidth || 1200;
  const height = surface.clientHeight || 560;
  const svgNS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(svgNS, "svg");
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.setAttribute("width", "100%");
  svg.setAttribute("height", "100%");

  const nodes = (graph.nodes || []).map((node, index) => ({
    ...node,
    x: width * (0.15 + (index % 5) * 0.18),
    y: height * (0.15 + (index % 7) * 0.11),
    vx: 0,
    vy: 0,
  }));
  const edges = graph.edges || [];
  const nodeById = new Map(nodes.map((node) => [node.id, node]));

  const links = edges.map((edge) => {
    const line = document.createElementNS(svgNS, "line");
    line.setAttribute("stroke", "#94a3b8");
    line.setAttribute("stroke-width", "1.6");
    line.setAttribute("opacity", "0.75");
    svg.appendChild(line);
    return { ...edge, line };
  });

  const groups = nodes.map((node) => {
    const group = document.createElementNS(svgNS, "g");
    group.style.cursor = "pointer";
    const circle = document.createElementNS(svgNS, "circle");
    circle.setAttribute("r", node.kind === "category" ? "20" : "14");
    circle.setAttribute("fill", node.color || "#2563eb");
    circle.setAttribute("stroke", "#ffffff");
    circle.setAttribute("stroke-width", "2");
    const label = document.createElementNS(svgNS, "text");
    label.setAttribute("text-anchor", "middle");
    label.setAttribute("dy", node.kind === "category" ? "38" : "30");
    label.setAttribute("font-size", "11");
    label.setAttribute("fill", "#0f172a");
    label.textContent = node.label || node.id;
    group.appendChild(circle);
    group.appendChild(label);
    group.addEventListener("click", async () => {
      if (!node.details_url) {
        return;
      }
      const response = await fetch(node.details_url, { headers: { "HX-Request": "true" } });
      document.querySelector("#detail-body").innerHTML = await response.text();
      const offcanvas = bootstrap.Offcanvas.getOrCreateInstance(document.querySelector("#detailCanvas"));
      offcanvas.show();
    });
    svg.appendChild(group);
    return { ...node, group, circle, label };
  });

  function tick() {
    for (const node of nodes) {
      node.vx += (width / 2 - node.x) * 0.0008;
      node.vy += (height / 2 - node.y) * 0.0008;
    }

    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i];
        const b = nodes[j];
        const dx = a.x - b.x;
        const dy = a.y - b.y;
        const dist = Math.max(60, Math.sqrt(dx * dx + dy * dy));
        const force = 1800 / (dist * dist);
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        a.vx += fx;
        a.vy += fy;
        b.vx -= fx;
        b.vy -= fy;
      }
    }

    for (const edge of edges) {
      const source = nodeById.get(edge.source);
      const target = nodeById.get(edge.target);
      if (!source || !target) {
        continue;
      }
      const dx = target.x - source.x;
      const dy = target.y - source.y;
      const dist = Math.max(1, Math.sqrt(dx * dx + dy * dy));
      const force = (dist - 150) * 0.002;
      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;
      source.vx += fx;
      source.vy += fy;
      target.vx -= fx;
      target.vy -= fy;
    }

    for (const node of nodes) {
      node.vx *= 0.92;
      node.vy *= 0.92;
      node.x = Math.min(width - 30, Math.max(30, node.x + node.vx));
      node.y = Math.min(height - 30, Math.max(30, node.y + node.vy));
    }

    for (const link of links) {
      const source = nodeById.get(link.source);
      const target = nodeById.get(link.target);
      if (!source || !target) {
        continue;
      }
      link.line.setAttribute("x1", source.x);
      link.line.setAttribute("y1", source.y);
      link.line.setAttribute("x2", target.x);
      link.line.setAttribute("y2", target.y);
    }

    for (const node of nodes) {
      const group = groups.find((item) => item.id === node.id);
      if (!group) {
        continue;
      }
      group.group.setAttribute("transform", `translate(${node.x},${node.y})`);
      group.circle.setAttribute("fill", node.color || "#2563eb");
    }

    requestAnimationFrame(tick);
  }

  surface.appendChild(svg);
  surface.dataset.graphRendered = "true";
  tick();
}

document.addEventListener("DOMContentLoaded", () => buildGraph(document.querySelector("#attack-path-graph")));
document.addEventListener("htmx:afterSwap", () => buildGraph(document.querySelector("#attack-path-graph")));

