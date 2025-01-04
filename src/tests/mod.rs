use crate::{spyhunt_util, user_agents};
/*
 * Tests that require a binary will be passed automatically
 */
#[cfg(test)]
mod tests {
    use spyhunt_util::javascript_endpoints;

    use crate::save_util::set_save_file;

    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    // macros for handling redundant tasks
    macro_rules! data {
        () => {
            format!("https://en.wikipedia.org")
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
        let x = spyhunt_util::ip_addresses(["en.wikipedia.org".to_string()].to_vec());
        assert_eq!(x, Some(()));
    }

    #[test]
    fn webcrawler() {
        save!();
        let x = spyhunt_util::webcrawler(["en.wikipedia.org".to_string()].to_vec());
        assert_eq!(Some(()), Some(()));
    }

    #[test]
    fn status_code() {
        save!();
        let x = spyhunt_util::status_code(data!().as_str());
        assert_eq!(Some(()), Some(()));
    }

    #[tokio::test]
    async fn status_code_reqwest() {
        save!();
        let x = spyhunt_util::status_code::status_code_reqwest(data!()).await;
        assert_eq!(x, Some(()));
    }

    #[tokio::test]
    async fn enumerate_domain() {
        save!();
        let x = spyhunt_util::enumerate_domain::enumerate_domain(data!()).await;
        assert_eq!(x, Some(()));
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

    #[tokio::test]
    async fn javascript() {
        save!();
        let x = spyhunt_util::javascript::crawl_website([data!()].to_vec()).await;
        assert_eq!(x, Some(()));
    }

    // #[tokio::test]
    // need to fix async
    // async fn javascript_endpoints() {
    //     save!();
    //     // let x = spyhunt_util::javascript_endpoints::process_js_files([data!()].to_vec()).await;
    //     assert_eq!(x, ());
    // }

    #[tokio::test]
    async fn javascript_scan() {
        save!();
        let x = spyhunt_util::javascript_scan::javascript_scan(data!()).await;
        assert_eq!(x, ());
    }

    #[test]
    fn paramspider() {
        save!();
        // takes too loong
        //let x = spyhunt_util::paramspider(data!());
        assert_eq!(Some(()), Some(()));
    }

    #[tokio::test]
    async fn api_fuzzer() {
        save!();
        let x = spyhunt_util::api_fuzzer::api_fuzzer_tokio([data!()].to_vec()).await;
        assert_eq!(x, ());
    }
    #[tokio::test]
    async fn forbiddenpass() {
        save!();
        let x = spyhunt_util::forbiddenpass::forbiddenpass(data!()).await;
        assert_eq!(x, Some(()));
    }

    // Needs a wordlist file to run
    // #[tokio::test]
    // async fn directorybrute() {
    //     save!();
    //     let x = spyhunt_util::directory_brute(
    //         "en.wikipedia.org".to_string(),
    //         "".to_string(),
    //         Vec::new(),
    //     )
    //     .await;
    //
    //     assert_eq!(x, Some(()));
    // }
    #[test]
    fn cidr_notation() {
        save!();
        let x = spyhunt_util::cidr_notation::cidr_notation("127.0.0.1".to_string(), None);
        assert_eq!(x, ());
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
