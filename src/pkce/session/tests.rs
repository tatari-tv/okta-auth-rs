use super::*;

// classify(has_tty, ssh, gui_likely) across the full input matrix.

#[test]
fn no_tty_is_non_interactive_regardless_of_other_signals() {
    for ssh in [false, true] {
        for gui in [false, true] {
            assert_eq!(
                classify(false, ssh, gui),
                Session::NonInteractive,
                "ssh={ssh} gui={gui}"
            );
        }
    }
}

#[test]
fn tty_with_gui_and_no_ssh_is_local() {
    assert_eq!(classify(true, false, true), Session::Local);
}

#[test]
fn tty_without_gui_is_headless() {
    assert_eq!(classify(true, false, false), Session::Headless);
}

#[test]
fn ssh_forces_headless_even_with_gui() {
    // An X11-forwarded SSH session has DISPLAY set (gui_likely=true) but is Headless.
    assert_eq!(classify(true, true, true), Session::Headless);
}

#[test]
fn ssh_without_gui_is_headless() {
    assert_eq!(classify(true, true, false), Session::Headless);
}
