use berbir_shared::{CreateScanRequest, Finding, Scan, ScanEvent, ScanKind, TemplateInfo};
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
                <span>"100% Rust vulnerability scanner"</span>
            </header>
            <ScanForm templates={templates} set_scans={set_scans} />
            <ScansList scans={scans} selected={selected} set_selected={set_selected} />
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

    let submit = move |_| {
        let target_value = target.get().trim().to_string();
        if target_value.is_empty() {
            set_error.set(Some("target required".to_string()));
            return;
        }
        set_error.set(None);
        set_busy.set(true);
        let scan_kind = kind.get();
        let set_busy = set_busy;
        let set_error = set_error;
        let set_scans = set_scans;
        spawn_local(async move {
            let req = CreateScanRequest {
                kind: scan_kind,
                target: target_value,
                ports: None,
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
                {move || format!("{} built-in signatures ready", templates.get().len())}
            </div>
            <Show when=move || error.get().is_some() fallback=|| ()>
                <div class="err">{move || error.get().unwrap_or_default()}</div>
            </Show>
        </div>
    }
}

#[component]
fn ScansList(
    scans: ReadSignal<Vec<Scan>>,
    selected: ReadSignal<Option<Uuid>>,
    set_selected: WriteSignal<Option<Uuid>>,
) -> impl IntoView {
    view! {
        <div class="panel">
            <h3 style="margin-top:0">"Scan history"</h3>
            <Show when=move || !scans.get().is_empty() fallback=|| view! {
                <div class="empty">"No scans yet — submit one above."</div>
            }>
                <table>
                    <thead>
                        <tr>
                            <th>"Target"</th>
                            <th>"Kind"</th>
                            <th>"Status"</th>
                            <th>"Findings"</th>
                            <th>"Started"</th>
                        </tr>
                    </thead>
                    <tbody>
                        {move || scans.get().iter().map(|s| {
                            let id = s.id;
                            let selected_row = selected.get() == Some(id);
                            let style = if selected_row { "background:rgba(88,166,255,0.10)" } else { "" };
                            view! {
                                <tr
                                    class="clickable"
                                    style=style
                                    on:click=move |_| set_selected.set(Some(id))
                                >
                                    <td>{s.target.clone()}</td>
                                    <td>{s.kind.as_str()}</td>
                                    <td><span class="status">{s.status.as_str()}</span></td>
                                    <td>{s.finding_count}</td>
                                    <td>{s.started_at.map(|t| t.format("%H:%M:%S").to_string()).unwrap_or_default()}</td>
                                </tr>
                            }
                        }).collect::<Vec<_>>()}
                    </tbody>
                </table>
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
                                if active_now == Some(scan_id) => {
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
