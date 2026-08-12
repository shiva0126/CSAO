function syncSelectionGroup(container, groupName) {
  const items = Array.from(
    container.querySelectorAll(`[data-multi-item="${groupName}"]`)
  );
  const selected = items.filter((item) => item.checked);
  const values = selected.map((item) => item.value);
  const labels = selected.map((item) => item.dataset.label || item.value);
  const hidden = container.querySelector(`[data-sync-target="${groupName}"]`);
  if (hidden) {
    hidden.value = values.join(",");
  }
  const summary = container.querySelector(`[data-selection-summary="${groupName}"]`);
  if (summary) {
    summary.innerHTML = labels.length
      ? labels.map((label) => `<span class="tag">${label}</span>`).join("")
      : '<span class="text-secondary">No selections yet.</span>';
  }
}

function bindSelectionGroups(container) {
  if (!container) {
    return;
  }

  const groups = new Set();
  container.querySelectorAll("[data-multi-item]").forEach((node) => {
    groups.add(node.dataset.multiItem);
    node.addEventListener("change", () => {
      syncSelectionGroup(container, node.dataset.multiItem);
    });
  });

  container.querySelectorAll("[data-select-all]").forEach((button) => {
    button.addEventListener("click", () => {
      const group = button.dataset.selectAll;
      container.querySelectorAll(`[data-multi-item="${group}"]`).forEach((node) => {
        node.checked = true;
      });
      syncSelectionGroup(container, group);
    });
  });

  container.querySelectorAll("[data-clear-all]").forEach((button) => {
    button.addEventListener("click", () => {
      const group = button.dataset.clearAll;
      container.querySelectorAll(`[data-multi-item="${group}"]`).forEach((node) => {
        node.checked = false;
      });
      syncSelectionGroup(container, group);
    });
  });

  container.querySelectorAll("[data-filter-check-group]").forEach((input) => {
    input.addEventListener("input", () => {
      const query = input.value.trim().toLowerCase();
      const group = input.dataset.filterCheckGroup;
      container
        .querySelectorAll(`[data-multi-group="${group}"] [data-check-option]`)
        .forEach((option) => {
          const text = (option.textContent || "").toLowerCase();
          option.hidden = Boolean(query) && !text.includes(query);
        });
    });
  });

  groups.forEach((group) => syncSelectionGroup(container, group));
}

function bindWizardState(root = document) {
  const wizard = root.querySelector("[data-assessment-wizard]");
  if (!wizard) {
    return;
  }

  const syncGroup = (groupName) => {
    syncSelectionGroup(wizard, groupName);
    const items = Array.from(wizard.querySelectorAll(`[data-multi-item="${groupName}"]`));
    const selected = items.filter((item) => item.checked);
    const labels = selected.map((item) => item.dataset.label || item.value);
    if (groupName === "regions") {
      const review = wizard.querySelector("[data-review-regions]");
      const summaryNode = wizard.querySelector("[data-summary-regions]");
      if (review) {
        review.textContent = labels.length ? labels.join(", ") : "Pending";
      }
      if (summaryNode) {
        summaryNode.textContent = `${labels.length} selected`;
      }
    }
    if (groupName === "services") {
      const review = wizard.querySelector("[data-review-services]");
      const count = wizard.querySelector("[data-estimate-services]");
      if (review) {
        review.textContent = labels.length ? labels.join(", ") : "Pending";
      }
      if (count) {
        count.textContent = String(labels.length);
      }
    }
    if (groupName === "collectors") {
      const review = wizard.querySelector("[data-review-collectors]");
      const summaryNode = wizard.querySelector("[data-summary-collectors]");
      const count = wizard.querySelector("[data-estimate-collectors]");
      if (review) {
        review.textContent = labels.length ? labels.join(", ") : "Pending";
      }
      if (summaryNode) {
        summaryNode.textContent = `${labels.length} selected`;
      }
      if (count) {
        count.textContent = String(labels.length);
      }
    }
    if (groupName === "report_types") {
      const review = wizard.querySelector("[data-review-reports]");
      const summaryNode = wizard.querySelector("[data-summary-reports]");
      if (review) {
        review.textContent = labels.length ? labels.join(", ") : "Pending";
      }
      if (summaryNode) {
        summaryNode.textContent = `${labels.length} selected`;
      }
    }
  };

  bindSelectionGroups(wizard);

  const nameInput = wizard.querySelector('input[name="name"]');
  const clientInput = wizard.querySelector('input[name="client"]');
  const accountSelect = wizard.querySelector('select[name="cloud_account_id"]');
  const riskSelect = wizard.querySelector('select[name="risk_profile"]');

  const bindTextMirror = (input, targetSelector, fallback = "Pending") => {
    if (!input) {
      return;
    }
    const target = wizard.querySelector(targetSelector);
    const update = () => {
      if (target) {
        target.textContent = input.value.trim() || fallback;
      }
    };
    input.addEventListener("input", update);
    input.addEventListener("change", update);
    update();
  };

  bindTextMirror(nameInput, "[data-review-name]");
  bindTextMirror(clientInput, "[data-review-client]");

  if (riskSelect) {
    const target = wizard.querySelector("[data-review-risk]");
    const update = () => {
      const selected = riskSelect.options[riskSelect.selectedIndex];
      if (target) {
        target.textContent = selected ? selected.textContent : "Pending";
      }
    };
    riskSelect.addEventListener("change", update);
    update();
  }

  if (accountSelect) {
    const target = wizard.querySelector("[data-review-account]");
    const update = () => {
      const selected = accountSelect.options[accountSelect.selectedIndex];
      if (target) {
        target.textContent =
          selected && selected.value ? selected.textContent : "Pending";
      }
    };
    accountSelect.addEventListener("change", update);
    update();
  }

  ["regions", "services", "collectors", "report_types"].forEach(syncGroup);
}

function bindAccountOnboarding(root = document) {
  const form = root.querySelector("[data-account-onboarding]");
  if (!form) {
    return;
  }
  bindSelectionGroups(form);

  const hiddenAuthType = form.querySelector("[data-auth-type-input]");
  const authInputs = Array.from(form.querySelectorAll("[data-auth-method]"));
  const authCards = Array.from(form.querySelectorAll("[data-auth-card]"));
  const authPanels = Array.from(form.querySelectorAll("[data-auth-panel]"));

  const syncAuthPanels = (selected) => {
    if (hiddenAuthType) {
      hiddenAuthType.value = selected;
    }
    authCards.forEach((card) => {
      const input = card.querySelector("[data-auth-method]");
      card.classList.toggle("selected", input && input.value === selected);
    });
    authPanels.forEach((panel) => {
      panel.classList.toggle("active", panel.dataset.authPanel === selected);
    });
  };

  authInputs.forEach((input) => {
    input.addEventListener("change", () => {
      if (input.checked) {
        syncAuthPanels(input.value);
      }
    });
  });

  const activeInput = authInputs.find((input) => input.checked) || authInputs[0];
  if (activeInput) {
    syncAuthPanels(activeInput.value);
  }
}

function bindSettingsForm(root = document) {
  const form = root.querySelector('form[hx-post="/api/settings"]');
  if (!form) {
    return;
  }
  bindSelectionGroups(form);
}

function bindAccessRequirements(root = document) {
  const shell = root.querySelector("[data-access-requirements]");
  if (!shell) {
    return;
  }

  shell.querySelectorAll("[data-copy-target]").forEach((button) => {
    button.addEventListener("click", async () => {
      const target = root.querySelector(`#${button.dataset.copyTarget}`);
      if (!target) {
        return;
      }
      const text = target.textContent || "";
      try {
        await navigator.clipboard.writeText(text);
        button.textContent = "Copied";
        window.setTimeout(() => {
          button.textContent = "Copy";
        }, 1200);
      } catch (_error) {
        button.textContent = "Copy Failed";
      }
    });
  });

  shell.querySelectorAll("[data-download-text]").forEach((button) => {
    button.addEventListener("click", () => {
      const target = root.querySelector(`#${button.dataset.downloadText}`);
      if (!target) {
        return;
      }
      const blob = new Blob([target.textContent || ""], { type: "text/plain;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = button.dataset.downloadFilename || "download.txt";
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    });
  });

  shell.querySelectorAll("[data-export-csv]").forEach((button) => {
    button.addEventListener("click", () => {
      const table = root.querySelector(`#${button.dataset.exportCsv}`);
      if (!table) {
        return;
      }
      const rows = Array.from(table.querySelectorAll("tr")).map((row) =>
        Array.from(row.querySelectorAll("th,td"))
          .map((cell) => `"${(cell.textContent || "").trim().replace(/"/g, '""')}"`)
          .join(",")
      );
      const blob = new Blob([rows.join("\n")], { type: "text/csv;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = button.dataset.exportFilename || "export.csv";
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    });
  });

  const search = shell.querySelector("[data-matrix-search]");
  const filter = shell.querySelector("[data-matrix-filter]");
  const table = shell.querySelector("[data-permission-matrix]");
  if (table && (search || filter)) {
    const rows = Array.from(table.querySelectorAll("tbody tr"));
    const applyFilter = () => {
      const query = (search?.value || "").trim().toLowerCase();
      const service = (filter?.value || "").trim().toLowerCase();
      rows.forEach((row) => {
        const text = (row.textContent || "").toLowerCase();
        const rowService = (row.dataset.service || "").toLowerCase();
        const matchesQuery = !query || text.includes(query);
        const matchesService = !service || rowService === service;
        row.style.display = matchesQuery && matchesService ? "" : "none";
      });
    };
    search?.addEventListener("input", applyFilter);
    filter?.addEventListener("change", applyFilter);
    applyFilter();
  }
}

document.addEventListener("htmx:afterSwap", () => {
  bindWizardState(document);
  bindAccountOnboarding(document);
  bindSettingsForm(document);
  bindAccessRequirements(document);
  if (window.bootstrap) {
    document.querySelectorAll('[data-bs-toggle="offcanvas"]').forEach((node) => {
      node.addEventListener("click", () => {
        const target = node.getAttribute("data-bs-target");
        if (target) {
          const element = document.querySelector(target);
          if (element) {
            bootstrap.Offcanvas.getOrCreateInstance(element).show();
          }
        }
      }, { once: true });
    });
  }
});

document.addEventListener("DOMContentLoaded", () => {
  bindWizardState(document);
  bindAccountOnboarding(document);
  bindSettingsForm(document);
  bindAccessRequirements(document);
});
