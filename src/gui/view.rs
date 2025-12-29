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

}