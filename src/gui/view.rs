use iced::widget::{
    button, column, container, pick_list, progress_bar, row, rule, scrollable, text, text_editor, text_input, toggler, Space,
};
use iced::{Alignment, Color, Element, Length};

use super::style;
use super::{App, FormField, Message, Page};
use crate::apikeys::Role;
use crate::core::checker::KeyReport;
use crate::system::Target;

type El<'a> = Element<'a, Message>;

fn title(s: &str) -> El<'_> {
    text(s).size(22).into()
}

fn subtitle(s: &str) -> El<'_> {
    text(s).size(13).style(style::muted).into()
}

fn card<'a>(content: impl Into<El<'a>>) -> El<'a> {
    container(content).padding(16).width(Length::Fill).style(style::card).into()
}

fn badge<'a>(label: impl Into<String>, color: Color) -> El<'a> {
    container(text(label.into()).size(12)).padding([2, 10]).style(style::badge(color)).into()
}

fn primary<'a>(label: &'a str, msg: Option<Message>) -> El<'a> {
    button(text(label).size(14)).padding([6, 16]).style(style::primary).on_press_maybe(msg).into()
}

fn secondary<'a>(label: &'a str, msg: Option<Message>) -> El<'a> {
    button(text(label).size(14)).padding([6, 16]).style(style::secondary).on_press_maybe(msg).into()
}

fn danger<'a>(label: &'a str, msg: Option<Message>) -> El<'a> {
    button(text(label).size(14)).padding([6, 14]).style(style::danger).on_press_maybe(msg).into()
}

fn input<'a>(placeholder: &str, value: &str) -> text_input::TextInput<'a, Message> {
    text_input(placeholder, value).padding([7, 10]).size(14).style(style::input)
}

fn switch<'a>(value: bool, label: &'a str) -> toggler::Toggler<'a, Message> {
    toggler(value).label(label).size(18).text_size(14).spacing(10).style(style::switch)
}

/// Fluent indeterminate progress bar: a short segment sweeping a 2 px track.
fn indeterminate(phase: f32) -> El<'static> {
    let total = 1000u16;
    let seg = 300u16;
    let pos = ((phase * (total + seg) as f32) as u16).min(total + seg);
    let lead = pos.saturating_sub(seg);
    let width = pos.min(seg).min(total.saturating_sub(lead)).max(1);
    let tail = total.saturating_sub(lead + width).max(1);
    container(
        row![
            Space::new().width(Length::FillPortion(lead.max(1))),
            container(Space::new()).width(Length::FillPortion(width)).height(2).style(style::bar),
            Space::new().width(Length::FillPortion(tail)),
        ]
        .height(2),
    )
    .width(Length::Fill)
    .height(2)
    .style(style::track)
    .into()
}

fn field<'a>(label: &'a str, value: String) -> El<'a> {
    row![
        text(label).size(13).width(150).style(style::muted),
        text(value).size(13).font(style::mono()),
    ]
    .spacing(8)
    .into()
}

fn status_badge(r: &KeyReport) -> El<'static> {
    if r.blocked {
        badge("Blocked", style::DANGER)
    } else if r.valid {
        badge("Valid", style::SUCCESS)
    } else {
        badge(r.status.label(), style::WARNING)
    }
}

impl App {
    pub(super) fn view(&self) -> El<'_> {
        let mut nav = column![
            row![
                iced::widget::image(iced::widget::image::Handle::from_bytes(style::LOGO_PNG)).width(32).height(32),
                column![text("PID Key Checker").size(17), subtitle(concat!("v", env!("CARGO_PKG_VERSION")))].spacing(0),
            ]
            .spacing(10)
            .align_y(Alignment::Center),
            Space::new().height(16),
        ]
        .spacing(4)
        .padding(16)
        .width(200);
        for (page, label, glyph) in Page::ALL {
            let active = self.page == page;
            let mut item = row![container(Space::new()).width(3).height(16).style(style::indicator(active))]
                .spacing(10)
                .align_y(Alignment::Center);
            if cfg!(windows) {
                item = item.push(text(glyph.to_string()).font(style::ICONS).size(16));
            }
            nav = nav.push(
                button(item.push(text(label).size(14)))
                    .width(Length::Fill)
                    .padding([8, 6])
                    .style(style::nav(active))
                    .on_press(Message::Navigate(page)),
            );
        }
        let sidebar = container(nav).height(Length::Fill).style(style::sidebar);

        let body: El = match (&self.load_error, self.page) {
            (_, Page::About) => self.about_page(),
            (Some(e), _) => card(column![title("Failed to load data"), text(e.clone()).style(style::colored(style::DANGER))].spacing(8)),
            (None, Page::Check) => self.check_page(),
            (None, Page::Batch) => self.batch_page(),
            (None, Page::Blocklist) => self.blocklist_page(),
            (None, Page::System) => self.system_page(),
            (None, Page::Server) => self.server_page(),
            (None, Page::ApiKeys) => self.keys_page(),
        };
        let main = container(scrollable(container(body).padding(24).width(Length::Fill)).height(Length::Fill))
            .width(Length::Fill)
            .height(Length::Fill);

        column![row![sidebar, main].height(Length::Fill), self.status_bar()].into()
    }

    fn status_bar(&self) -> El<'_> {
        let db = self
            .services
            .as_ref()
            .map(|s| {
                let st = s.checker.stats();
                format!(
                    "{} products · {} pkeyconfigs · {} blocked keys · legacy keys: {}",
                    st.configurations,
                    st.files,
                    s.checker.blocklist().len(),
                    if s.checker.legacy_supported() { "pidgenx" } else { "unavailable" }
                )
            })
            .unwrap_or_default();
        let server = match &self.server {
            Some(h) => badge(format!("API ● http://{}", h.addr), style::SUCCESS),
            None => badge("API stopped", style::MUTED),
        };
        container(
            row![
                text(self.os_name.clone()).size(12),
                text(db).size(12),
                Space::new().width(Length::Fill),
                text(self.notice.clone().unwrap_or_default()).size(12),
                server,
            ]
            .spacing(16)
            .align_y(Alignment::Center),
        )
        .padding([6, 16])
        .width(Length::Fill)
        .style(style::status_bar)
        .into()
    }

    fn check_page(&self) -> El<'_> {
        let can_check = !self.checking && !self.key_input.trim().is_empty();
        let key_row = row![
            input("XXXXX-XXXXX-XXXXX-XXXXX-XXXXX", &self.key_input)
                .on_input(Message::KeyInput)
                .on_paste(Message::KeyInput)
                .on_submit(Message::Check)
                .font(style::mono())
                .size(16)
                .padding([9, 12]),
            primary(if self.checking { "Checking…" } else { "Check Key" }, can_check.then_some(Message::Check)),
        ]
        .spacing(10)
        .align_y(Alignment::Center);

        let options = row![
            switch(self.online, "Online MAK count / blocked check").on_toggle(Message::Online),
            Space::new().width(Length::Fill),
            secondary("Install & Activate (Windows)", (!self.key_input.is_empty()).then_some(Message::Install(Target::Windows))),
            secondary("Install & Activate (Office)", (!self.key_input.is_empty()).then_some(Message::Install(Target::Office))),
        ]
        .spacing(10)
        .align_y(Alignment::Center);

        let mut page = column![
            title("Key Checker"),
            subtitle("Detects the product from the key's group ID and validates it against the exact pkeyconfig."),
            card(column![key_row, options].spacing(12)),
        ]
        .spacing(14);

        if self.checking {
            page = page.push(indeterminate(self.phase));
        }
        if let Some(r) = &self.report {
            page = page.push(self.report_card(r));
        }
        if let Some(log) = &self.action_log {
            page = page.push(card(column![
                text("Install / activation output").size(15),
                container(text(log.clone()).font(style::mono()).size(12)).padding(10).width(Length::Fill).style(style::console),
            ].spacing(8)));
        }
        page.into()
    }

    fn report_card<'a>(&'a self, r: &'a KeyReport) -> El<'a> {
        let mut header = row![
            text(r.key.clone().unwrap_or_else(|| r.input.clone())).size(18).font(style::mono()),
            status_badge(r),
        ]
        .spacing(12)
        .align_y(Alignment::Center);
        if let Some(d) = &r.details
            && !d.key_type.is_empty() {
                header = header.push(badge(d.key_type.clone(), style::ACCENT));
            }
        header = header.push(Space::new().width(Length::Fill));
        header = header.push(secondary("Copy report", self.report_text().map(Message::CopyText)));

        let mut col = column![header].spacing(6);
        if !r.valid {
            col = col.push(text(r.message.clone()).style(style::colored(style::WARNING)));
        }
        if let Some(d) = &r.details {
            col = col.push(rule::horizontal(1));
            for (label, value) in [
                ("Product", format!("{} [{}]", d.product, d.category)),
                ("Description", d.description.clone()),
                ("Edition ID", d.edition_id.clone()),
                ("License type", d.key_type.clone()),
                ("Channel", d.channel.clone()),
                ("Part number", d.part_number.clone()),
                ("Product ID", d.product_id.clone()),
                ("Extended PID", d.extended_pid.clone()),
                ("SKU ID", d.sku_id.clone()),
                ("Crypto ID", if d.crypto_id > 0 { format!("{} (0x{})", d.crypto_id, d.crypto_id_hex) } else { String::new() }),
                ("Serial", d.serial.map(|s| s.to_string()).unwrap_or_default()),
                ("Security value", d.security_value.clone().map(|s| format!("0x{s}")).unwrap_or_default()),
                ("PKeyConfig", d.pkeyconfig.clone()),
            ] {
                if !value.trim().is_empty() && value != " []" {
                    col = col.push(field(label, value));
                }
            }
            if !d.license_note.is_empty() {
                col = col.push(text(d.license_note.clone()).size(13).style(style::muted));
            }
        }
        col = col.push(rule::horizontal(1));
        let mak = match (&r.activation, &r.activation_error) {
            (Some(a), _) => match (a.remaining, &a.error_code) {
                (Some(n), _) => format!("{n} activations remaining"),
                (None, Some(c)) => format!("Not available ({c}){}", a.error_message.as_ref().map(|m| format!(" — {m}")).unwrap_or_default()),
                _ => "Not available".into(),
            },
            (None, Some(e)) => format!("Error: {e}"),
            (None, None) => "Not queried (only MAK keys are checked online)".into(),
        };
        col = col.push(field("Activation count", mak));
        col = col.push(row![
            text("Blocked").size(13).width(150).style(style::muted),
            if r.blocked {
                text(r.blocked_reason.clone().unwrap_or_else(|| "Yes".into())).size(13).style(style::colored(style::DANGER))
            } else {
                text("No").size(13).style(style::colored(style::SUCCESS))
            }
        ].spacing(8));
        col = col.push(
            text(if r.cached {
                format!("Cached result from {} (checked in {} µs)", r.checked_at.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M:%S"), r.elapsed_us)
            } else {
                format!("Checked in {} µs", r.elapsed_us)
            })
            .size(11)
            .style(style::muted),
        );
        card(col)
    }

    fn batch_page(&self) -> El<'_> {
        let count = super::extract_keys(&self.batch_input.text()).len();
        let editor = text_editor(&self.batch_input)
            .placeholder("Paste keys or any text containing keys — they are detected automatically")
            .on_action(Message::BatchEdit)
            .font(style::mono())
            .height(180);
        let controls = row![
            primary(if self.batch_running { "Checking…" } else { "Check All" }, (!self.batch_running && count > 0).then_some(Message::BatchCheck)),
            secondary("Clear", Some(Message::BatchClear)),
            secondary("Copy CSV", (!self.batch_results.is_empty()).then(|| Message::CopyText(super::to_csv(&self.batch_results)))),
            secondary("Export CSV", (!self.batch_results.is_empty()).then_some(Message::BatchExport)),
            Space::new().width(Length::Fill),
            switch(self.online, "Online MAK check").on_toggle(Message::Online),
            text(format!("{count} keys detected (max {})", self.config.checker.max_batch_size)).size(13).style(style::muted),
        ]
        .spacing(10)
        .align_y(Alignment::Center);

        let mut page = column![
            title("Batch Check"),
            subtitle("Offline validation runs in parallel; MAK counts are fetched in a few combined requests."),
            card(column![editor, controls].spacing(12)),
        ]
        .spacing(14);

        if self.batch_running {
            let done = self.batch_results.len();
            page = page.push(card(
                column![
                    row![
                        text(format!("Checking… {done} / {} keys", self.batch_total)).size(14),
                        Space::new().width(Length::Fill),
                        text(format!("{:.0}%", done as f32 * 100.0 / self.batch_total.max(1) as f32)).size(13).style(style::muted),
                    ],
                    progress_bar(0.0..=self.batch_total.max(1) as f32, done as f32).girth(4).style(style::progress),
                ]
                .spacing(8),
            ));
        }
        if let Some(r) = self.selected.and_then(|i| self.batch_results.get(i)) {
            page = page.push(column![
                row![
                    text("Selected key").size(15),
                    Space::new().width(Length::Fill),
                    secondary("Close", Some(Message::SelectResult(None))),
                ]
                .align_y(Alignment::Center),
                self.report_card(r),
            ].spacing(8));
        }

        if !self.batch_results.is_empty() {
            let valid = self.batch_results.iter().filter(|r| r.valid).count();
            let blocked = self.batch_results.iter().filter(|r| r.blocked).count();
            let header = row![
                text(format!("{} results", self.batch_results.len())).size(15),
                badge(format!("{valid} valid"), style::SUCCESS),
                badge(format!("{blocked} blocked"), style::DANGER),
                badge(format!("{} invalid", self.batch_results.len() - valid), style::WARNING),
                Space::new().width(Length::Fill),
                text(format!("{:.1} ms", self.batch_elapsed_ms)).size(13).style(style::muted),
            ]
            .spacing(10)
            .align_y(Alignment::Center);
            let mut table = column![row![
                text("Key").width(270).size(12).style(style::muted),
                text("Status").width(110).size(12).style(style::muted),
                text("Product / description").width(Length::Fill).size(12).style(style::muted),
                text("Type").width(120).size(12).style(style::muted),
                text("MAK").width(90).size(12).style(style::muted),
            ]
            .padding([4, 8])]
            .spacing(2);
            for (i, r) in self.batch_results.iter().enumerate() {
                let d = r.details.as_ref();
                let mak = r
                    .activation
                    .as_ref()
                    .map(|a| a.remaining.map(|n| n.to_string()).or(a.error_code.clone()).unwrap_or_else(|| "-".into()))
                    .or(r.activation_error.as_ref().map(|_| "error".into()))
                    .unwrap_or_default();
                table = table.push(
                    button(
                        row![
                            text(r.key.clone().unwrap_or_else(|| r.input.clone())).width(270).size(13).font(style::mono()),
                            container(status_badge(r)).width(110),
                            text(d.map(|d| if d.description.is_empty() { r.message.clone() } else { d.description.clone() }).unwrap_or_else(|| r.message.clone()))
                                .width(Length::Fill)
                                .size(13),
                            text(d.map(|d| d.key_type.clone()).unwrap_or_default()).width(120).size(13),
                            text(mak).width(90).size(13),
                        ]
                        .align_y(Alignment::Center),
                    )
                    .width(Length::Fill)
                    .padding([4, 8])
                    .style(style::list_row(i % 2 == 0, self.selected == Some(i)))
                    .on_press(Message::SelectResult(Some(i))),
                );
            }
            page = page.push(card(column![header, subtitle("Click a key to see its full report."), table].spacing(10)));
        }
        page.into()
    }

    fn blocklist_page(&self) -> El<'_> {
        let total = self.services.as_ref().map(|s| s.checker.blocklist().len()).unwrap_or(0);
        let has_input = !self.block_input.text().trim().is_empty();
        let editor = text_editor(&self.block_input)
            .placeholder("One or more keys, one per line")
            .on_action(Message::BlockEdit)
            .font(style::mono())
            .height(160);
        let actions = row![
            input("Note / source (optional, e.g. ticket #42)", &self.block_note).on_input(Message::BlockNote),
            primary("Add to blocklist", has_input.then_some(Message::BlockAdd)),
            danger("Remove", has_input.then_some(Message::BlockRemove)),
            secondary("Look up", has_input.then_some(Message::BlockLookup)),
        ]
        .spacing(10)
        .align_y(Alignment::Center);
        let mut page = column![
            row![title("Blocked Keys"), Space::new().width(Length::Fill), badge(format!("{total} keys"), style::DANGER)]
                .align_y(Alignment::Center),
            subtitle("Stored in a redb database. Keys Microsoft reports as blocked (0x67) or from revoked ranges are recorded automatically (see Settings)."),
            card(column![editor, actions].spacing(12)),
        ]
        .spacing(14);
        if let Some(s) = &self.block_status {
            page = page.push(card(text(s.clone()).font(style::mono()).size(13)));
        }
        page.into()
    }

    fn system_page(&self) -> El<'_> {
        let mut page = column![
            row![
                title("This PC"),
                Space::new().width(Length::Fill),
                secondary(if self.sys_loading { "Loading…" } else { "Refresh" }, (!self.sys_loading).then_some(Message::SysRefresh)),
                secondary("Detailed info (slmgr /dlv)", Some(Message::SysDetails)),
            ]
            .spacing(10)
            .align_y(Alignment::Center),
            subtitle("Windows and Office licenses installed on this machine (Software Protection Platform)."),
        ]
        .spacing(14);
        if let Some(e) = &self.sys_error {
            page = page.push(card(text(e.clone()).style(style::colored(style::DANGER))));
        }
        for l in &self.licenses {
            let color = if l.status.starts_with("Licensed") { style::SUCCESS } else { style::WARNING };
            page = page.push(card(
                column![
                    row![text(l.name.clone()).size(16), Space::new().width(Length::Fill), badge(l.status.clone(), color)]
                        .align_y(Alignment::Center),
                    field("Description", l.description.clone()),
                    field("SKU ID", l.sku_id.clone()),
                    field("Partial key", l.partial_key.clone()),
                    field("Channel", l.channel.clone()),
                    field("Grace remaining", if l.grace_minutes > 0 { format!("{} days", l.grace_minutes / 1440) } else { "-".into() }),
                ]
                .spacing(4),
            ));
        }
        if let Some(d) = &self.sys_details {
            page = page.push(card(container(text(d.clone()).font(style::mono()).size(12)).padding(10).width(Length::Fill).style(style::console)));
        }
        page.into()
    }

    fn server_page(&self) -> El<'_> {
        let f = &self.form;
        let running = self.server.is_some();
        let input = |label: &'static str, value: &str, msg: fn(String) -> FormField| -> El<'_> {
            column![
                text(label).size(12).style(style::muted),
                input("", value).on_input(move |v| Message::Form(msg(v))),
            ]
            .spacing(4)
            .width(Length::FillPortion(1))
            .into()
        };
        let switch = |label: &'static str, value: bool, msg: fn(bool) -> FormField| -> El<'_> {

}