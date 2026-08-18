use std::collections::{BTreeSet, HashMap};

use berbir_shared::{
    CreateScanRequest, Finding, Scan, ScanEvent, ScanKind, ScanMode, TemplateInfo,
};
use leptos::ev::MouseEvent;
use leptos::prelude::*;
use leptos::task::spawn_local;
use uuid::Uuid;

use crate::api;

#[component]
pub fn App() -> impl IntoView {
    let (scans, set_scans) = signal(Vec::<Scan>::new());
    let (templates, set_templates) = signal(Vec::<TemplateInfo>::new());
    let (selected, set_selected) = signal(None::<Uuid>);

    spawn_local(async move {
        if let Ok(list) = api::list_scans().await {
            set_scans.set(list);
        }
    });
    spawn_local(async move {
        if let Ok(list) = api::list_templates().await {
            set_templates.set(list);
        }
    });

    std::mem::forget(gloo_timers::callback::Interval::new(3000, move || {
        wasm_bindgen_futures::spawn_local(async move {
            if let Ok(list) = api::list_scans().await {
                set_scans.set(list);
            }
        });
    }));

    view! {
        <div class="wrap">
            <header>
                <h1>"berbir"</h1>
                <span>"vulnerability scanner"</span>
            </header>
            <ScanForm templates={templates} set_scans={set_scans} />
            <ScansList scans={scans} selected={selected} set_selected={set_selected} set_scans={set_scans} />
            <FindingsView selected={selected} />
        </div>
    }
}

#[component]
fn ScanForm(
    templates: ReadSignal<Vec<TemplateInfo>>,
    set_scans: WriteSignal<Vec<Scan>>,
) -> impl IntoView {
    let (target, set_target) = signal(String::new());
    let (kind, set_kind) = signal(ScanKind::Url);
    let (error, set_error) = signal(None::<String>);
    let (busy, set_busy) = signal(false);
    let (search, set_search) = signal(String::new());
    let (selected_templates, set_selected_templates) = signal(BTreeSet::<String>::new());
    let (mode, set_mode) = signal(Some(ScanMode::Simple));
    let (show_templates, set_show_templates) = signal(false);

    let select_mode = move |m: Option<ScanMode>| {
        set_mode.set(m);
        set_show_templates.set(m.is_none());
    };

    let submit = move |_| {
        let target_value = target.get().trim().to_string();
        if target_value.is_empty() {
            set_error.set(Some("target required".to_string()));
            return;
        }
        set_error.set(None);
        set_busy.set(true);
        let scan_kind = kind.get();
        let mode = mode.get();
        let template_ids = selected_templates.get();
        let set_busy = set_busy;
        let set_error = set_error;
        let set_scans = set_scans;
        spawn_local(async move {
            let req = CreateScanRequest {
                kind: scan_kind,
                target: target_value,
                ports: None,
                template_ids: match mode {
                    Some(_) => None,
                    None if template_ids.is_empty() => None,
                    None => Some(template_ids.into_iter().collect()),
                },
                mode,
            };
            match api::create_scan(req).await {
                Ok(_) => {
                    if let Ok(list) = api::list_scans().await {
                        set_scans.set(list);
                    }
                }
                Err(e) => set_error.set(Some(e)),
            }
            set_busy.set(false);
        });
    };

    let clear_selection = move |_| set_selected_templates.update(|s| s.clear());

    let toggle_template = move |tid: String, checked: bool| {
        set_selected_templates.update(|s| {
            if checked {
                s.insert(tid);
            } else {
                s.remove(&tid);
            }
        });
        set_mode.set(None);
    };

    view! {
        <div class="panel">
            <div class="row">
                <input
                    type="text"
                    placeholder="Target — https://example.com, example.com, 203.0.113.7"
                    prop:value=move || target.get()
                    on:input=move |ev| set_target.set(event_target_value(&ev))
                />
                <select
                    on:change=move |ev| {
                        let v = event_target_value(&ev);
                        set_kind.set(match v.as_str() {
                            "domain" => ScanKind::Domain,
                            "port_scan" => ScanKind::PortScan,
                            _ => ScanKind::Url,
                        });
                    }
                >
                    <option value="url">"URL scan"</option>
                    <option value="domain">"Domain (subdomains)"</option>
                    <option value="port_scan">"Host port scan"</option>
                </select>
                <button
                    class="primary"
                    disabled=move || busy.get()
                    on:click=submit
                >
                    {move || if busy.get() { "Scanning…" } else { "Scan" }}
                </button>
            </div>
            <div class="muted" style="font-size:12px; margin-top:8px">
                {move || format!("{} templates ready", templates.get().len())}
            </div>
            <Show when=move || kind.get() != ScanKind::PortScan fallback=|| ()>
                <div class="tpl-picker">
                    <div class="row mode-btns" style="gap:6px; flex-wrap:wrap">
                        <span class="muted" style="font-size:12px">"mode:"</span>
                        {move || {
                            let list = templates.get();
                            let total = list.len();
                            let count = |m: ScanMode| {
                                list.iter()
                                    .filter(|t| berbir_shared::template_matches_mode(m, &t.tags))
                                    .count()
                            };
                            let current = mode.get();
                            let cls = move |m: Option<ScanMode>| {
                                if current == m { "mode-btn active" } else { "mode-btn" }
                            };
                            view! {
                                <button class={cls(Some(ScanMode::Simple))} on:click=move |_| select_mode(Some(ScanMode::Simple))>
                                    {format!("Simple — {}", fmt_count(count(ScanMode::Simple)))}
                                </button>
                                <button class={cls(Some(ScanMode::Medium))} on:click=move |_| select_mode(Some(ScanMode::Medium))>
                                    {format!("Medium — {}", fmt_count(count(ScanMode::Medium)))}
                                </button>
                                <button class={cls(Some(ScanMode::Deep))} on:click=move |_| select_mode(Some(ScanMode::Deep))>
                                    {format!("Deep — {}", fmt_count(total))}
                                </button>
                                <button class={cls(None)} on:click=move |_| select_mode(None)>
                                    "Custom"
                                </button>
                            }
                        }}
                    </div>
                    <div class="row" style="gap:8px; flex-wrap: wrap">
                        <span class="muted" style="font-size:12px">
                            {move || {
                                let total = templates.get().len();
                                match mode.get() {
                                    Some(m) => format!("{m:?} mode — {} templates", fmt_count(total)),
                                    None => {
                                        let sel = selected_templates.get();
                                        if sel.is_empty() {
                                            format!("custom: all {} templates", fmt_count(total))
                                        } else {
                                            format!(
                                                "custom: {} of {} selected",
                                                fmt_count(sel.len()),
                                                fmt_count(total)
                                            )
                                        }
                                    }
                                }
                            }}
                        </span>
                        <Show when=move || mode.get().is_some() fallback=|| ()>
                            <button class="toggle-btn" on:click=move |_| set_show_templates.update(|v| *v = !*v)>
                                {move || if show_templates.get() { "Hide templates" } else { "Show templates" }}
                            </button>
                        </Show>
                        <Show when=move || mode.get().is_none() && !selected_templates.get().is_empty() fallback=|| ()>
                            <button class="toggle-btn" title="Run all templates" on:click=clear_selection>
                                "Clear selection"
                            </button>
                        </Show>
                    </div>
                    <Show when=move || mode.get().is_none() || show_templates.get() fallback=|| ()>
                        <input
                            type="text"
                            placeholder="Filter templates by id or name…"
                            prop:value=move || search.get()
                            on:input=move |ev| set_search.set(event_target_value(&ev))
                        />
                    <div class="tpl-list">
                        {move || {
                            let q = search.get().to_lowercase();
                            let list = templates.get();
                            let filtered = list
                                .iter()
                                .filter(|t| {
                                    q.is_empty()
                                        || t.id.to_lowercase().contains(&q)
                                        || t.name.to_lowercase().contains(&q)
                                })
                                .collect::<Vec<_>>();
                            let total = filtered.len();
                            let shown = if q.is_empty() { 200.min(total) } else { total };
                            filtered
                                .into_iter()
                                .take(shown)
                                .map(|t| {
                                    let tid = t.id.clone();
                                    let t_name = t.name.clone();
                                    let checked = selected_templates.get().contains(&tid);
                                    let badge = format!("badge b-{}", t.severity);
                                    let toggle_tid = tid.clone();
                                    let toggle = move |ev: web_sys::Event| {
                                        toggle_template(toggle_tid.clone(), event_target_checked(&ev));
                                    };
                                    view! {
                                        <label class="tpl-row">
                                            <input
                                                type="checkbox"
                                                prop:checked=checked
                                                on:change=toggle
                                            />
                                            <span class={badge}>{t.severity.clone()}</span>
                                            <code>{tid}</code>
                                            <span class="muted tpl-name">{t_name}</span>
                                        </label>
                                    }
                                })
                                .collect::<Vec<_>>()
                        }}
                    </div>
                    <div class="muted" style="font-size:11px">
                        {move || {
                            let q = search.get();
                            let total = templates.get().len();
                            if q.is_empty() {
                                if total > 200 {
                                    format!("showing the first 200 of {total} — type to search the rest")
                                } else {
                                    String::new()
                                }
                            } else {
                                format!("{} matching templates", {
                                    let q = q.to_lowercase();
                                    templates
                                        .get()
                                        .iter()
                                        .filter(|t| {
                                            t.id.to_lowercase().contains(&q)
                                                || t.name.to_lowercase().contains(&q)
                                        })
                                        .count()
                                })
                            }
                        }}
                    </div>
                    </Show>
                </div>
            </Show>
            <Show when=move || error.get().is_some() fallback=|| ()>
                <div class="err">{move || error.get().unwrap_or_default()}</div>
            </Show>
        </div>
    }
}

fn fmt_count(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn trash_icon() -> impl IntoView {
    view! {
        <svg
            xmlns="http://www.w3.org/2000/svg"
            width="14"
            height="14"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
        >
            <polyline points="3 6 5 6 21 6"/>
            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
        </svg>
    }
}

#[component]
fn ScansList(
    scans: ReadSignal<Vec<Scan>>,
    selected: ReadSignal<Option<Uuid>>,
    set_selected: WriteSignal<Option<Uuid>>,
    set_scans: WriteSignal<Vec<Scan>>,
) -> impl IntoView {
    let (collapsed, set_collapsed) = signal(HashMap::<Uuid, bool>::new());

    let on_delete = move |id: Uuid| {
        let set_scans = set_scans;
        let set_selected = set_selected;
        let selected = selected;
        let set_collapsed = set_collapsed;
        spawn_local(async move {
            if api::delete_scan(id).await.is_ok()
                && let Ok(list) = api::list_scans().await
            {
                if let Some(s) = selected.get()
                    && !list.iter().any(|x| x.id == s)
                {
                    set_selected.set(None);
                }
                set_collapsed.update(|m| m.retain(|k, _| list.iter().any(|x| x.id == *k)));
                set_scans.set(list);
            }
        });
    };

    view! {
        <div class="panel">
            <h3 style="margin-top:0">"Scan history"</h3>
            <Show when=move || !scans.get().is_empty() fallback=|| view! {
                <div class="empty">"No scans yet — submit one above."</div>
            }>
                <div class="scan-grid">
                    {move || {
                        let list = scans.get();
                        let mut by_parent: HashMap<Uuid, Vec<Scan>> = HashMap::new();
                        for s in &list {
                            if let Some(pid) = s.parent_scan_id {
                                by_parent.entry(pid).or_default().push(s.clone());
                            }
                        }
                        list.into_iter()
                            .filter(|s| s.parent_scan_id.is_none())
                            .map(|s| {
                                let kids = by_parent.remove(&s.id).unwrap_or_default();
                                let has_kids = !kids.is_empty();
                                let kid_count = kids.len();
                                let count = if has_kids {
                                    kids.iter().map(|k| k.finding_count).sum::<i64>()
                                } else {
                                    s.finding_count
                                };
                                let selected_here = selected.get() == Some(s.id);
                                let card_class = if selected_here {
                                    "scan-card selected"
                                } else {
                                    "scan-card"
                                };
                                let sid = s.id;
                                let s_target = s.target.clone();
                                let s_kind = s.kind.as_str();
                                let s_status = s.status.as_str();
                                let s_started = s
                                    .started_at
                                    .map(|t| t.format("%H:%M:%S").to_string())
                                    .unwrap_or_default();
                                let select_card = move |_| set_selected.set(Some(sid));
                                let delete_card = move |ev: MouseEvent| {
                                    ev.stop_propagation();
                                    on_delete(sid);
                                };
                                let toggle_children = move |ev: MouseEvent| {
                                    ev.stop_propagation();
                                    set_collapsed.update(|m| {
                                        let e = m.entry(sid).or_insert(true);
                                        *e = !*e;
                                    });
                                };
                                view! {
                                    <div class=card_class on:click=select_card>
                                        <div class="card-head">
                                            <div>
                                                <span class="card-target">{s_target}</span>
                                                <span class="muted">" (" {s_kind} ")"</span>
                                            </div>
                                            <div class="row" style="gap:8px">
                                                <Show when=move || has_kids fallback=|| ()>
                                                    <button
                                                        class="toggle-btn"
                                                        title="Toggle child scans"
                                                        on:click=toggle_children
                                                    >
                                                        {move || {
                                                            if collapsed.get().get(&sid).copied().unwrap_or(true) {
                                                                "▸"
                                                            } else {
                                                                "▾"
                                                            }
                                                        }}
                                                        <span class="muted">
                                                            {move || format!("{} {}", kid_count, if kid_count == 1 { "child" } else { "children" })}
                                                        </span>
                                                    </button>
                                                </Show>
                                                <span class="status">{s_status}</span>
                                                <span class="muted">{count} " findings"</span>
                                                <span class="muted">{s_started}</span>
                                                <button class="delete-btn" title="Delete scan" on:click=delete_card>{trash_icon()}</button>
                                            </div>
                                        </div>
                                        <Show when=move || has_kids && !collapsed.get().get(&sid).copied().unwrap_or(true) fallback=|| ()>
                                            <div class="children">
                                                {kids.iter().map(|c| {
                                                    let cid = c.id;
                                                    let c_selected = selected.get() == Some(cid);
                                                    let c_class = if c_selected {
                                                        "child-card selected"
                                                    } else {
                                                        "child-card"
                                                    };
                                                    let c_target = c.target.clone();
                                                    let c_status = c.status.as_str();
                                                    let c_count = c.finding_count;
                                                    let select_child = move |_| set_selected.set(Some(cid));
                                                    let delete_child = move |ev: MouseEvent| {
                                                        ev.stop_propagation();
                                                        on_delete(cid);
                                                    };
                                                    view! {
                                                        <div class=c_class on:click=select_child>
                                                            <div class="card-head">
                                                                <span class="card-target">{c_target}</span>
                                                                <div class="row" style="gap:8px">
                                                                    <span class="status">{c_status}</span>
                                                                    <span class="muted">{c_count} " findings"</span>
                                                                    <button class="delete-btn" title="Delete scan" on:click=delete_child>{trash_icon()}</button>
                                                                </div>
                                                            </div>
                                                        </div>
                                                    }
                                                }).collect::<Vec<_>>()}
                                            </div>
                                        </Show>
                                    </div>
                                }
                            })
                            .collect::<Vec<_>>()
                    }}
                </div>
            </Show>
        </div>
    }
}

#[component]
fn FindingsView(selected: ReadSignal<Option<Uuid>>) -> impl IntoView {
    let (scan, set_scan) = signal(None::<Scan>);
    let (findings, set_findings) = signal(Vec::<Finding>::new());
    let active = RwSignal::new(None::<Uuid>);

    Effect::new(move |_| {
        let id = selected.get();
        match id {
            None => {
                active.set(None);
                set_scan.set(None);
                set_findings.set(Vec::new());
            }
            Some(id) => {
                active.set(Some(id));
                set_scan.set(None);
                set_findings.set(Vec::new());
                let set_scan = set_scan;
                let set_findings = set_findings;
                spawn_local(async move {
                    if let Ok(detail) = api::get_scan(id).await {
                        set_scan.set(Some(detail.scan));
                        set_findings.set(detail.findings);
                    }
                    crate::ws::open_scan_ws(id, move |event| {
                        let active_now = active.get();
                        match event {
                            ScanEvent::Finding(f) => {
                                if active_now == Some(f.scan_id) {
                                    set_findings.update(|list| {
                                        if !list.iter().any(|x| x.id == f.id) {
                                            list.push(f);
                                        }
                                    });
                                }
                            }
                            ScanEvent::StatusChange { scan_id, status }
                                if active_now == Some(scan_id) =>
                            {
                                set_scan.update(|s| {
                                    if let Some(s) = s {
                                        s.status = status;
                                    }
                                });
                            }
                            _ => {}
                        }
                    });
                });
            }
        }
    });

    view! {
        <Show when=move || scan.get().is_some() fallback=|| ()>
            {move || scan.get().map(|s| {
                let s_id = s.id;
                view! {
                    <div class="panel">
                        <div class="row">
                            <h3 style="margin:0">
                                {format!("Findings — {}", s.target)}
                                <span class="muted">" (" {s.kind.as_str()} ")"</span>
                            </h3>
                            <a href={format!("/api/scans/{s_id}/report.md")}>"Download report"</a>
                        </div>
                        <div class="muted" style="font-size:12px; margin:8px 0">
                            {move || format!("status: {} · findings: {}", s.status.as_str(), findings.get().len())}
                        </div>
                        <Show when=move || !findings.get().is_empty() fallback=|| view! {
                            <div class="empty">"No findings yet — live feed attached."</div>
                        }>
                            <table>
                                <thead>
                                    <tr>
                                        <th>"Severity"</th>
                                        <th>"Template"</th>
                                        <th>"URL"</th>
                                        <th>"Evidence"</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {move || findings.get().iter().map(|f| {
                                        let sev = f.severity.as_str();
                                        let badge = format!("badge b-{sev}");
                                        let dot = format!("severity-dot s-{sev}");
                                        let url = f.url.clone();
                                        view! {
                                            <tr>
                                                <td>
                                                    <span class={dot}></span>
                                                    <span class={badge}>{sev}</span>
                                                </td>
                                                <td>{f.template_id.clone()}</td>
                                                <td><a href={url.clone()} target="_blank">{url.clone()}</a></td>
                                                <td>{f.evidence.clone()}</td>
                                            </tr>
                                        }
                                    }).collect::<Vec<_>>()}
                                </tbody>
                            </table>
                        </Show>
                    </div>
                }
            })}
        </Show>
    }
}
