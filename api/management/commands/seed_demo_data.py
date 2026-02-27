import random
import uuid
import os
from datetime import timedelta

from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone
from django.contrib.auth.hashers import make_password
from django.conf import settings

from api.models import Category, PlayEvent, Playlist, PlaylistTrack, PremiumSettings, Subscription, Track, User


class Command(BaseCommand):
    help = "Seed demo/mock data for dashboard + users analytics (development only)."

    def add_arguments(self, parser):
        parser.add_argument("--users", type=int, default=120)
        parser.add_argument("--tracks", type=int, default=35)
        parser.add_argument("--playlists", type=int, default=8)
        parser.add_argument("--days", type=int, default=180)
        parser.add_argument("--events", type=int, default=2500)

    def handle(self, *args, **options):
        now = timezone.now()
        days = max(int(options["days"]), 30)
        user_count = max(int(options["users"]), 10)
        track_count = max(int(options["tracks"]), 10)
        playlist_count = max(int(options["playlists"]), 1)
        event_count = max(int(options["events"]), 100)

        random.seed(42)

        with transaction.atomic():
            self._seed_premium_settings()
            categories = self._seed_categories()
            users = self._seed_users(now, days, user_count)
            tracks = self._seed_tracks(now, days, track_count, categories)
            self._seed_playlists(now, playlist_count, tracks)
            self._seed_subscriptions(now, days, users)
            self._seed_play_events(now, days, event_count, users, tracks)

        self.stdout.write(self.style.SUCCESS("Seed complete."))

    def _seed_premium_settings(self):
        row = PremiumSettings.objects.first()
        if row is None:
            PremiumSettings.objects.create(
                subscription_price="2.99",
                free_trial_days=7,
                auto_lock_new_content=False,
                allow_gifting=True,
            )

    def _seed_categories(self):
        defaults = ["Seerah", "Quran", "Hadith", "Fiqh", "History", "Dua"]
        out = []
        for name in defaults:
            cat, _ = Category.objects.get_or_create(name=name)
            out.append(cat)
        return out

    def _seed_users(self, now, days, count):
        out = []
        # Create 1 admin and 1 manager for UI testing.
        admin, _ = User.objects.get_or_create(
            email="admin-demo@seerahpod.local",
            defaults={
                "auth_provider": User.AuthProvider.EMAIL,
                "role": User.Role.ADMIN,
                "status": User.Status.ACTIVE,
                "password_hash": make_password("Admin@123"),
            },
        )
        manager, _ = User.objects.get_or_create(
            email="manager-demo@seerahpod.local",
            defaults={
                "auth_provider": User.AuthProvider.EMAIL,
                "role": User.Role.MANAGER,
                "status": User.Status.ACTIVE,
                "password_hash": make_password("Admin@123"),
            },
        )
        out.extend([admin, manager])

        # Regular users
        for idx in range(count):
            email = f"demo-user-{idx:03d}@seerahpod.local"
            user, _ = User.objects.get_or_create(
                email=email,
                defaults={
                    "auth_provider": User.AuthProvider.EMAIL,
                    "role": User.Role.USER,
                    "status": User.Status.ACTIVE,
                    "password_hash": make_password("User@123"),
                },
            )
            created_at = now - timedelta(days=random.randint(0, days))
            # Around 70% have recent activity.
            last_login_at = (
                now - timedelta(days=random.randint(0, 30))
                if random.random() < 0.7
                else now - timedelta(days=random.randint(31, days))
            )
            # Small % blocked/deleted for filtering.
            status = User.Status.ACTIVE
            r = random.random()
            if r < 0.06:
                status = User.Status.BLOCKED
            elif r < 0.08:
                status = User.Status.DELETED
            User.objects.filter(id=user.id).update(
                created_at=created_at,
                last_login_at=last_login_at,
                status=status,
                updated_at=now,
            )
            user.refresh_from_db()
            out.append(user)
        return out

    def _seed_tracks(self, now, days, count, categories):
        out = []
        media_root = getattr(settings, "MEDIA_ROOT", None)
        existing_audio_urls = []
        existing_cover_urls = []
        if media_root:
            audio_dir = os.path.join(media_root, "audio_tracks")
            cover_dir = os.path.join(media_root, "track_covers")

            if os.path.isdir(audio_dir):
                existing_audio_urls = [
                    f"/media/audio_tracks/{name}"
                    for name in os.listdir(audio_dir)
                    if os.path.isfile(os.path.join(audio_dir, name))
                ]
            if os.path.isdir(cover_dir):
                existing_cover_urls = [
                    f"/media/track_covers/{name}"
                    for name in os.listdir(cover_dir)
                    if os.path.isfile(os.path.join(cover_dir, name))
                ]

        for idx in range(count):
            title = f"Demo Track {idx + 1}"
            speaker = random.choice(["Bharat", "Aisha", "Umar", "Hassan", "Maryam"])
            duration = random.randint(180, 3600)
            audio_url = (
                random.choice(existing_audio_urls)
                if existing_audio_urls
                else f"/media/audio_tracks/demo-{uuid.uuid4()}.mp3"
            )
            cover_image_url = random.choice(existing_cover_urls) if existing_cover_urls else None
            track = Track.objects.create(
                title=title,
                speaker_name=speaker,
                description="Seeded demo track.",
                audio_url=audio_url,
                cover_image_url=cover_image_url,
                duration_seconds=duration,
                category=random.choice(categories),
                is_premium=(random.random() < 0.25),
                status=Track.Status.PUBLISHED,
                visibility=Track.Visibility.PUBLIC,
            )
            created_at = now - timedelta(days=random.randint(0, days))
            Track.objects.filter(id=track.id).update(created_at=created_at, updated_at=now)
            track.refresh_from_db()
            out.append(track)
        return out

    def _seed_playlists(self, now, count, tracks):
        for idx in range(count):
            playlist = Playlist.objects.create(
                title=f"Demo Playlist {idx + 1}",
                description="Seeded demo playlist.",
                cover_image_url=f"/media/playlist_covers/demo-{uuid.uuid4()}.png",
                visibility=Playlist.Visibility.PUBLIC,
                is_active=True,
            )
            Playlist.objects.filter(id=playlist.id).update(created_at=now, updated_at=now)
            chosen = random.sample(tracks, k=min(8, len(tracks)))
            PlaylistTrack.objects.bulk_create(
                [
                    PlaylistTrack(playlist=playlist, track=track, position=pos)
                    for pos, track in enumerate(chosen)
                ]
            )

    def _seed_subscriptions(self, now, days, users):
        # Clear existing demo subscriptions to avoid duplicates
        Subscription.objects.filter(user__email__startswith="demo-user-").delete()

        regular_users = [u for u in users if u.role == User.Role.USER and u.status == User.Status.ACTIVE]
        for u in regular_users:
            r = random.random()
            if r < 0.12:
                # Trial
                started_at = now - timedelta(days=random.randint(0, 20))
                ends_at = started_at + timedelta(days=7)
                Subscription.objects.create(
                    user=u,
                    plan_name="Trial",
                    provider=Subscription.Provider.RAZORPAY,
                    status=Subscription.Status.TRIAL,
                    started_at=started_at,
                    ends_at=ends_at,
                    auto_renew=True,
                )
            elif r < 0.20:
                # Active premium
                started_at = now - timedelta(days=random.randint(0, days))
                ends_at = started_at + timedelta(days=30)
                sub = Subscription.objects.create(
                    user=u,
                    plan_name="Premium",
                    provider=Subscription.Provider.RAZORPAY,
                    status=Subscription.Status.ACTIVE,
                    started_at=started_at,
                    ends_at=ends_at,
                    auto_renew=True,
                )
                # Align created_at to started_at for analytics grouping.
                Subscription.objects.filter(id=sub.id).update(created_at=started_at)

    def _seed_play_events(self, now, days, count, users, tracks):
        # Keep existing real events; add demo events.
        demo_users = [u for u in users if u.email.startswith("demo-user-") and u.status == User.Status.ACTIVE]
        if not demo_users or not tracks:
            return

        # Prefer tracks with media files that actually exist on disk, so dashboard "play" doesn't 404.
        playable_tracks = []
        media_root = getattr(settings, "MEDIA_ROOT", None)
        if media_root:
            for t in tracks:
                url = t.audio_url or ""
                if not url.startswith("/media/"):
                    continue
                rel = url[len("/media/") :].lstrip("/").replace("/", os.sep)
                full_path = os.path.join(media_root, rel)
                if os.path.exists(full_path):
                    playable_tracks.append(t)
        if playable_tracks:
            tracks = playable_tracks

        events = []
        for _ in range(count):
            user = random.choice(demo_users)
            track = random.choice(tracks)
            created_at = now - timedelta(days=random.randint(0, days))
            total = max(int(track.duration_seconds or 0), 60)
            played = random.randint(10, min(total, 600))
            completion = round((played / total) * 100.0, 2)
            events.append(
                PlayEvent(
                    user=user,
                    track=track,
                    session_id=uuid.uuid4(),
                    played_seconds=played,
                    total_duration=total,
                    completion_percentage=completion,
                    source=random.choice([PlayEvent.Source.HOME, PlayEvent.Source.SEARCH, PlayEvent.Source.PLAYLIST]),
                    device_platform=random.choice([PlayEvent.DevicePlatform.ANDROID, PlayEvent.DevicePlatform.IOS]),
                    created_at=created_at,
                )
            )
        created = PlayEvent.objects.bulk_create(events)
        return len(created)
