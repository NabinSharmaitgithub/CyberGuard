import requests
import threading
from tqdm import tqdm

SOCIALS = {
    "500px": "https://500px.com/%s",
    "About me": "https://about.me/%s",
    "AngelList": "https://angel.co/%s",
    "Anime planet": "https://www.anime-planet.com/users/%s",
    "Awwwards": "https://awwwards.com/%s/",
    "Badoo": "https://badoo.com/en/%s",
    "Behance": "https://behance.net/%s",
    "Bitbucket": "https://bitbucket.org/%s",
    "Blogger": "https://%s.blogspot.com",
    "Bluesky": "https://bsky.app/profile/%s",
    "BuyMeACoffe": "https://buymeacoffee.com/%s",
    "Buzzfeed": "https://buzzfeed.com/%s",
    "Canva": "https://www.canva.com/%s",
    "CashMe": "https://cash.me/%s",
    "Chess": "https://www.chess.com/member/%s",
    "Codecademy": "https://codecademy.com/%s",
    "Codementor": "https://www.codementor.io/%s",
    "Creativemarket": "https://creativemarket.com/%s",
    "DailyMotion": "https://www.dailymotion.com/%s",
    "Deviantart": "https://%s.deviantart.com",
    "Disqus": "https://disqus.com/%s",
    "Dribbble": "https://dribbble.com/%s",
    "Duolingo": "https://www.duolingo.com/profile/%s?via=share_profile",
    "Ebay": "https://ebay.com/usr/%s",
    "Ello": "https://ello.co/%s",
    "Etsy": "https://www.etsy.com/shop/%s",
    "Facebook": "https://facebook.com/%s",
    "Fiverr": "https://fiverr.com/%s",
    "Flickr": "https://flickr.com/people/%s",
    "Flipboard": "https://flipboard.com/@%s",
    "Foursquare": "https://foursquare.com/%s",
    "Fotolog": "https://fotolog.com/%s",
    "Github": "https://github.com/%s",
    "Gitlab": "https://gitlab.com/%s",
    "GoodReads": "https://www.goodreads.com/%s",
    "Google plus": "https://plus.google.com/+%s/posts",
    "Gravatar": "https://en.gravatar.com/%s",
    "Gumroad": "https://www.gumroad.com/%s",
    "Hacker news": "https://news.ycombinator.com/user?id=%s",
    "Imgur": "https://imgur.com/user/%s",
    "Instructables": "https://www.instructables.com/member/%s",
    "Instagram": "https://instagram.com/%s",
    "KeyBase": "https://keybase.io/%s",
    "Kongregate": "https://kongregate.com/accounts/%s",
    "Last.fm": "https://last.fm/user/%s",
    "LinkedIn": "https://linkedin.com/in/%s",
    "Linktree": "https://linktr.ee/%s",
    "Mastodon": "https://mastodon.uno/@%s",
    "Medium": "https://medium.com/@%s",
    "Minecrat": "https://playerdb.co/api/player/minecrat/%s",
    "Mixcloud": "https://www.mixcloud.com/%s",
    "Modrinth": "https://modrinth.com/user/%s",
    "Newgrounds": "https://%s.newgrounds.com",
    "Ngl": "https://ngl.link/%s",
    "Npm": "https://npmjs.com/~%s",
    "Onlyfans": "https://onlyfans.com/%s",
    "Patreon": "https://patreon.com/%s",
    "Pastebin": "https://pastebin.com/u/%s",
    "Paypal": "https://paypal.com/paypalme/%s",
    "Pinterest": "https://pinterest.com/%s",
    "Playstation network": "https://psnprofiles.com/%s",
    "Pornhub": "https://www.pornhub.com/users/%s",
    "Reddit": "https://reddit.com/user/%s",
    "Roblox": "https://roblox.com/user.aspx?username=%s",
    "Rumble": "https://rumble.com/user/%s",
    "Scribd": "https://www.scribd.com/%s",
    "Slack": "https://%s.slack.com",
    "Slideshare": "https://slideshare.net/%s",
    "Snapchat": "https://eelinsonice.appspot.com/web/deeplink/snapcode?username=%s",
    "Soundcloud": "https://soundcloud.com/%s",
    "Spotiy": "https://open.spotify.com/user/%s",
    "Steam": "https://steamcommunity.com/id/%s",
    "Telegram": "https://t.me/%s",
    "Threads": "https://threads.net/@%s",
    "Tiktok": "https://tiktok.com/@%s",
    "Tinder": "https://tinder.com/@%s",
    "Trakt": "https://www.trakt.tv/users/%s",
    "Tripadvisor": "https://tripadvisor.com/members/%s",
    "Tumblr": "https://%s.tumblr.com",
    "Twitch": "https://twitch.tv/%s",
    "Vimeo": "https://vimeo.com/%s",
    "VK": "https://vk.com/%s",
    "Wattpad": "https://www.wattpad.com/user/%s",
    "Wikipedia": "https://wikipedia.org/wiki/User:%s",
    "X": "https://x.com/%s",
    "Xbox gamertag": "https://www.xboxgamertag.com/search/%s",
    "Xvideos": "https://www.xvideos.com/profiles/%s",
    "Youtube": "https://youtube.com/%s",
}

def find_username(username, timeout=5, threads=10):
    found_urls = {}

    def check_url(social, url_format):
        url = url_format % username
        try:
            response = requests.get(url, timeout=timeout)
            if response.status_code == 200:
                found_urls[social] = url
        except requests.RequestException:
            pass

    with tqdm(total=len(SOCIALS), desc="Searching for username") as pbar:
        for i in range(0, len(SOCIALS), threads):
            batch = list(SOCIALS.items())[i:i+threads]
            thread_list = []
            for social, url_format in batch:
                thread = threading.Thread(target=check_url, args=(social, url_format))
                thread_list.append(thread)
                thread.start()
            
            for thread in thread_list:
                thread.join()
            
            pbar.update(len(batch))

    return found_urls
