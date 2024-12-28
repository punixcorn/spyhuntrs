use crate::{spyhunt_util, user_agents};
/*
 * Tests that require a binary will be passed automatically
 */
#[cfg(test)]
mod tests {
    use crate::save_util::set_save_file;

    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    // macros for handling redundant tasks
    macro_rules! data {
        () => {
            format!("en.wikipedia.com")
        };
    }

    macro_rules! save {
        () => {
            set_save_file("savefile.txt");
        };
    }

    #[test]
    fn get_reverse_ip() {
        save!();
        let x = spyhunt_util::get_reverse_ip(["8.8.8.8"].to_vec());
        assert_eq!(x, Some(()));
    }

    #[test]
    fn ip_addresses() {
        save!();
        let x = spyhunt_util::ip_addresses(["en.wikipedia.com".to_string()].to_vec());
        assert_eq!(x, Some(()));
    }

    #[test]
    fn webcrawler() {
        save!();
        let x = spyhunt_util::webcrawler(["en.wikipedia.com"].to_vec());
        assert_eq!(Some(()), Some(()));
    }

    #[test]
    fn status_code() {
        save!();
        let x = spyhunt_util::status_code("en.wikipedia.com");
        assert_eq!(Some(()), Some(()));
    }

    #[tokio::test]
    async fn status_code_reqwest() {
        save!();
        let x = spyhunt_util::status_code_reqwest("en.wikipedia.com").await;
        assert_eq!(x, Some(()));
    }

    #[tokio::test]
    async fn enumerate_domain() {
        save!();
        let x = spyhunt_util::enumerate_domain("en.wikipedia.com").await;
        assert_ne!(x.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn get_favicon_hash() {
        save!();
        let x = spyhunt_util::get_favicon_hash(data!()).await;
        assert_eq!(x, Some(()));
    }

    #[test]
    fn nmap() {
        save!();
        let x = spyhunt_util::nmap(data!());
        assert_eq!(Some(()), Some(()));
    }

    #[test]
    fn paramspider() {
        save!();
        let x = spyhunt_util::paramspider(data!());
        assert_eq!(Some(()), Some(()));
    }

    #[tokio::test]
    async fn google() {
        save!();
        let x = spyhunt_util::google(data!()).await;
        assert_eq!(x, Some(()));
    }

    #[test]
    fn print_all_ips() {
        save!();
        let x = spyhunt_util::print_all_ips("192.168.1.0/24");
        assert_eq!(x, Some(()));
    }
}
