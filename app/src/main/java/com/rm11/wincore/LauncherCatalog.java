package com.rm11.wincore;

/** Official publisher links only; installers and trademarks are not distributed with this app. */
public final class LauncherCatalog {
    private LauncherCatalog() {}

    public static final class Launcher {
        public final String id;
        public final String name;
        public final String officialUrl;
        public final String description;

        Launcher(String id, String name, String officialUrl, String description) {
            this.id = id;
            this.name = name;
            this.officialUrl = officialUrl;
            this.description = description;
        }
    }

    public static final Launcher[] ALL = {
        new Launcher("steam", "Steam", "https://store.steampowered.com/about/",
            "مشغّل Valve الرسمي لألعاب الكمبيوتر"),
        new Launcher("ubisoft", "Ubisoft Connect", "https://www.ubisoft.com/en-us/ubisoft-connect",
            "مشغّل Ubisoft الرسمي، ومنها The Crew Motorfest"),
        new Launcher("ea", "EA app", "https://www.ea.com/ea-app",
            "مشغّل Electronic Arts الرسمي، ومنها ألعاب Battlefield"),
        new Launcher("rockstar", "Rockstar Games Launcher", "https://www.rockstargames.com/downloads",
            "مشغّل Rockstar الرسمي، ومنها سلسلة Grand Theft Auto")
    };
}
