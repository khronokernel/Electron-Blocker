"""
build.py: Build script for Electron Blocker
"""

import argparse
import subprocess
import macos_pkg_builder
import mac_signing_buddy


class BuildMusicIsIllegal:

    def __init__(self, notarization_team_id: str = None, notarization_apple_id: str = None, notarization_password: str = None):
        self._notarization_team_id = notarization_team_id
        self._notarization_apple_id = notarization_apple_id
        self._notarization_password = notarization_password

        self._file_structure = {
            "build/Release/Electron-Blocker.app": "/Library/PrivilegedHelperTools/Electron-Blocker.app",
            "extras/launch services/com.khronokernel.electron-blocker.daemon.plist": "/Library/LaunchDaemons/com.khronokernel.electron-blocker.daemon.plist",
        }
        self._version = self._version_from_constants()


    def _version_from_constants(self) -> str:
        """
        Fetch version from Constants.swift
        """
        file = "electron-blocker/Library/Constants.swift"
        with open(file, "r") as f:
            for line in f:
                if "let projectVersion" not in line:
                    continue
                return line.split('"')[1]

        raise Exception("Failed to fetch version from Constants.swift")


    def _installer_pkg_welcome_message(self) -> str:
        """
        Generate installer README message for PKG
        """
        message = [
            "# Overview",
            f"This package will install 'Electron Blocker' (v{self._version}) on your system. This utility attempts to block Electron applications being exploited.\n",
            "Note: Upon installation, you will need to provide the application with Full Disk Access in System Settings. Once completed, you can restart the associated launch daemon or reinstall this PKG to apply changes.\n",
            "# Files Installed",
            "Installation of this package will add the following files to your system:\n",
        ]

        for item in self._file_structure:
            if self._file_structure[item].startswith("/tmp/"):
                continue
            message.append(f"* `{self._file_structure[item]}`\n")

        return "\n".join(message)


    def _xcodebuild(self):
        """
        Build application
        """
        print("Building Electron Blocker")
        subprocess.run(["/bin/rm", "-rf", "build"], check=True)
        subprocess.run(["/usr/bin/xcodebuild"], check=True)

        if all([
            self._notarization_team_id,
            self._notarization_apple_id,
            self._notarization_password,
        ]):
            mac_signing_buddy.Notarize(
                file="build/Release/Electron-Blocker.app",
                apple_id=self._notarization_apple_id,
                password=self._notarization_password,
                team_id=self._notarization_team_id,
            ).sign()


    def _package(self):
        """
        Convert application to package
        """
        print("Packaging Electron Blocker")
        assert macos_pkg_builder.Packages(
            pkg_output="Electron-Blocker-Installer.pkg",
            pkg_bundle_id="com.khronokernel.electron-blocker",
            pkg_file_structure=self._file_structure,
            pkg_allow_relocation=False,
            pkg_preinstall_script="extras/install scripts/remove.sh",
            pkg_postinstall_script="extras/install scripts/install.sh",
            pkg_signing_identity="Developer ID Installer: Mykola Grymalyuk (S74BDJXQMD)",
            pkg_as_distribution=True,
            pkg_title="Electron Blocker",
            pkg_version=self._version,
            pkg_welcome=self._installer_pkg_welcome_message(),
        ).build() is True

        print("Packaging uninstaller")
        assert macos_pkg_builder.Packages(
            pkg_output="Electron-Blocker-Uninstaller.pkg",
            pkg_bundle_id="com.khronokernel.electron-blocker.uninstall",
            pkg_preinstall_script="extras/install scripts/remove.sh",
            pkg_signing_identity="Developer ID Installer: Mykola Grymalyuk (S74BDJXQMD)",
            pkg_as_distribution=True,
            pkg_version=self._version,
            pkg_title="Electron Blocker Uninstaller",
        ).build() is True

        if all([
            self._notarization_team_id,
            self._notarization_apple_id,
            self._notarization_password,
        ]):
            mac_signing_buddy.Notarize(
                file="Electron-Blocker-Installer.pkg",
                apple_id=self._notarization_apple_id,
                password=self._notarization_password,
                team_id=self._notarization_team_id,
            ).sign()

            mac_signing_buddy.Notarize(
                file="Electron-Blocker-Uninstaller.pkg",
                apple_id=self._notarization_apple_id,
                password=self._notarization_password,
                team_id=self._notarization_team_id,
            ).sign()



    def run(self):
        self._xcodebuild()
        self._package()



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build script for Electron Blocker")
    parser.add_argument("--notarization-team-id", help="The Team ID to use for notarization", default=None)
    parser.add_argument("--notarization-apple-id", help="The Apple ID to use for notarization", default=None)
    parser.add_argument("--notarization-password", help="The password for the Apple ID", default=None)
    args = parser.parse_args()

    BuildMusicIsIllegal(
        notarization_team_id=args.notarization_team_id,
        notarization_apple_id=args.notarization_apple_id,
        notarization_password=args.notarization_password,
    ).run()
