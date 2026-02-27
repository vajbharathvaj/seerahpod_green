import re

from django.core.files.uploadedfile import SimpleUploadedFile
from django.contrib.auth.hashers import check_password, make_password
from django.core import mail
from django.test import override_settings
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase

from .models import AdminAuditLog, AdminSession, Category, PlayEvent, Playlist, PlaylistClickEvent, PlaylistTrack, RecommendationRule, SearchLog, SupportMessage, SupportTicket, Track, TrackCoverImage, User, UserMfaBackupCode, UserMfaTotp, UserNotification, UserSession, UserSettings, UserTrackLike


class AdminAuthAuditTests(APITestCase):
    def setUp(self):
        self.client.defaults['HTTP_HOST'] = 'localhost'
        self.admin_user = User.objects.create(
            email='admin-auth-audit@seerahpod.local',
            auth_provider=User.AuthProvider.EMAIL,
            role=User.Role.ADMIN,
            status=User.Status.ACTIVE,
            password_hash=make_password('Admin@123'),
        )

    def test_login_success_creates_audit_log(self):
        response = self.client.post(
            '/api/v1/admin/auth/login/',
            data={'email': self.admin_user.email, 'password': 'Admin@123'},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(
            AdminAuditLog.objects.filter(
                admin=self.admin_user,
                action='admin.login.success',
                entity_type='admin_session',
            ).exists()
        )

    def test_login_invalid_password_creates_audit_log(self):
        response = self.client.post(
            '/api/v1/admin/auth/login/',
            data={'email': self.admin_user.email, 'password': 'WrongPassword'},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertTrue(
            AdminAuditLog.objects.filter(
                admin=self.admin_user,
                action='admin.login.failed_password',
                entity_type='user',
                entity_id=self.admin_user.id,
            ).exists()
        )

    def test_refresh_and_logout_create_audit_logs(self):
        session = AdminSession.objects.create(
            user=self.admin_user,
            access_token='x' * 64,
            refresh_token='y' * 64,
            access_expires_at=timezone.now() + timezone.timedelta(minutes=30),
            refresh_expires_at=timezone.now() + timezone.timedelta(days=30),
        )

        refresh_response = self.client.post(
            '/api/v1/admin/auth/refresh/',
            data={'refresh_token': session.refresh_token},
            format='json',
        )
        self.assertEqual(refresh_response.status_code, status.HTTP_200_OK)
        self.assertTrue(
            AdminAuditLog.objects.filter(
                admin=self.admin_user,
                action='admin.token.refresh.success',
                entity_type='admin_session',
                entity_id=session.id,
            ).exists()
        )

        new_access_token = refresh_response.data['access_token']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {new_access_token}')
        logout_response = self.client.post('/api/v1/admin/auth/logout/', format='json')
        self.assertEqual(logout_response.status_code, status.HTTP_200_OK)
        self.assertTrue(
            AdminAuditLog.objects.filter(
                admin=self.admin_user,
                action='admin.logout',
                entity_type='admin_session',
                entity_id=session.id,
            ).exists()
        )


class UserAuthTests(APITestCase):
    def setUp(self):
        self.client.defaults['HTTP_HOST'] = 'localhost'

    @staticmethod
    def _latest_email_otp_code():
        if not mail.outbox:
            return None
        body = mail.outbox[-1].body or ''
        match = re.search(r'\b(\d{6})\b', body)
        return match.group(1) if match else None

    def test_signup_creates_user_and_session(self):
        response = self.client.post(
            '/api/v1/auth/signup/',
            data={'email': 'mobile-user@seerahpod.local', 'password': 'User@1234'},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(response.data['ok'])
        self.assertTrue(User.objects.filter(email='mobile-user@seerahpod.local').exists())
        self.assertTrue(UserSession.objects.filter(user__email='mobile-user@seerahpod.local').exists())
        self.assertEqual(response.data['user']['username'], 'mobile-user')

    def test_login_returns_tokens_for_existing_user(self):
        user = User.objects.create(
            email='mobile-login@seerahpod.local',
            auth_provider=User.AuthProvider.EMAIL,
            role=User.Role.USER,
            status=User.Status.ACTIVE,
            password_hash=make_password('User@1234'),
        )
        response = self.client.post(
            '/api/v1/auth/login/',
            data={'email': user.email, 'password': 'User@1234'},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['ok'])
        self.assertIn('access_token', response.data)
        self.assertIn('refresh_token', response.data)

    def test_login_accepts_username_identifier(self):
        user = User.objects.create(
            email='mobile-login-username@seerahpod.local',
            username='mobile_login_username',
            auth_provider=User.AuthProvider.EMAIL,
            role=User.Role.USER,
            status=User.Status.ACTIVE,
            password_hash=make_password('User@1234'),
        )
        response = self.client.post(
            '/api/v1/auth/login/',
            data={'email': user.username, 'password': 'User@1234'},
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['ok'])
        self.assertEqual(response.data['user']['id'], str(user.id))

    def test_me_requires_token_and_returns_user(self):
        user = User.objects.create(
            email='mobile-me@seerahpod.local',
            auth_provider=User.AuthProvider.EMAIL,
            role=User.Role.USER,
            status=User.Status.ACTIVE,
            password_hash=make_password('User@1234'),
        )
        session = UserSession.objects.create(
            user=user,
            access_token='u' * 64,
            refresh_token='v' * 64,
            access_expires_at=timezone.now() + timezone.timedelta(minutes=30),
            refresh_expires_at=timezone.now() + timezone.timedelta(days=30),
        )

        unauthorized = self.client.get('/api/v1/auth/me/')
        self.assertEqual(unauthorized.status_code, status.HTTP_401_UNAUTHORIZED)

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {session.access_token}')
        authorized = self.client.get('/api/v1/auth/me/')
        self.assertEqual(authorized.status_code, status.HTTP_200_OK)
        self.assertEqual(authorized.data['user']['email'], user.email)
        self.assertTrue(authorized.data['user']['has_password'])

    def test_me_returns_has_password_false_for_social_account(self):
        user = User.objects.create(
            email='mobile-me-google@seerahpod.local',
            username='mobile_me_google',
            auth_provider=User.AuthProvider.GOOGLE,
            provider_id='google-sub-1',
            role=User.Role.USER,
            status=User.Status.ACTIVE,
            is_email_verified=True,
        )
        session = UserSession.objects.create(
            user=user,
            access_token='gg' * 32,
            refresh_token='gh' * 32,
            access_expires_at=timezone.now() + timezone.timedelta(minutes=30),
            refresh_expires_at=timezone.now() + timezone.timedelta(days=30),
        )

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {session.access_token}')
        response = self.client.get('/api/v1/auth/me/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data['user']['has_password'])

    def test_refresh_and_logout(self):
        user = User.objects.create(
            email='mobile-refresh@seerahpod.local',
            auth_provider=User.AuthProvider.EMAIL,
            role=User.Role.USER,
            status=User.Status.ACTIVE,
            password_hash=make_password('User@1234'),
        )
        session = UserSession.objects.create(
            user=user,
            access_token='m' * 64,
            refresh_token='n' * 64,
            access_expires_at=timezone.now() + timezone.timedelta(minutes=30),
            refresh_expires_at=timezone.now() + timezone.timedelta(days=30),
        )

        refresh_response = self.client.post(
            '/api/v1/auth/refresh/',
            data={'refresh_token': session.refresh_token},
            format='json',
        )
        self.assertEqual(refresh_response.status_code, status.HTTP_200_OK)
        self.assertNotEqual(refresh_response.data['access_token'], session.access_token)

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh_response.data["access_token"]}')
        logout_response = self.client.post('/api/v1/auth/logout/', format='json')
        self.assertEqual(logout_response.status_code, status.HTTP_200_OK)

    def test_me_patch_updates_username(self):
        user = User.objects.create(
            email='mobile-profile@seerahpod.local',
            auth_provider=User.AuthProvider.EMAIL,
            role=User.Role.USER,
            status=User.Status.ACTIVE,
            password_hash=make_password('User@1234'),
        )
        session = UserSession.objects.create(
            user=user,
            access_token='up' * 32,
            refresh_token='ur' * 32,
            access_expires_at=timezone.now() + timezone.timedelta(minutes=30),
            refresh_expires_at=timezone.now() + timezone.timedelta(days=30),
        )

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {session.access_token}')
        response = self.client.patch(
            '/api/v1/auth/me/',
            data={'username': 'New.Profile_Name'},
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['ok'])
        self.assertEqual(response.data['user']['username'], 'new.profile_name')
        user.refresh_from_db()
        self.assertEqual(user.username, 'new.profile_name')

    def test_me_patch_rejects_duplicate_username(self):
        first = User.objects.create(
            email='mobile-profile-a@seerahpod.local',
            username='duplicate_name',
            auth_provider=User.AuthProvider.EMAIL,
            role=User.Role.USER,
            status=User.Status.ACTIVE,
            password_hash=make_password('User@1234'),
        )
        second = User.objects.create(
            email='mobile-profile-b@seerahpod.local',
            username='other_name',
            auth_provider=User.AuthProvider.EMAIL,
            role=User.Role.USER,
            status=User.Status.ACTIVE,
            password_hash=make_password('User@1234'),
        )
        session = UserSession.objects.create(
            user=second,
            access_token='du' * 32,
            refresh_token='dr' * 32,
            access_expires_at=timezone.now() + timezone.timedelta(minutes=30),
            refresh_expires_at=timezone.now() + timezone.timedelta(days=30),
        )

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {session.access_token}')
        response = self.client.patch('/api/v1/auth/me/', data={'username': first.username}, format='json')
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)

    def test_password_change_rotates_sessions_and_updates_hash(self):
        user = User.objects.create(
            email='mobile-password@seerahpod.local',
            username='mobile_password_user',
            auth_provider=User.AuthProvider.EMAIL,
            role=User.Role.USER,
            status=User.Status.ACTIVE,
            password_hash=make_password('User@1234'),
        )
        session = UserSession.objects.create(
            user=user,
            access_token='pc' * 32,
            refresh_token='pr' * 32,
            access_expires_at=timezone.now() + timezone.timedelta(minutes=30),
            refresh_expires_at=timezone.now() + timezone.timedelta(days=30),
        )

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {session.access_token}')
        response = self.client.post(
            '/api/v1/auth/password/change/',
            data={
                'current_password': 'User@1234',
                'new_password': 'User@5678',
                'confirm_password': 'User@5678',
            },
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['ok'])
        self.assertNotEqual(response.data['access_token'], session.access_token)
        self.assertNotEqual(response.data['refresh_token'], session.refresh_token)
        user.refresh_from_db()
        self.assertTrue(check_password('User@5678', user.password_hash))
        session.refresh_from_db()
        self.assertIsNotNone(session.revoked_at)

    def test_password_change_rejects_wrong_current_password(self):
        user = User.objects.create(
            email='mobile-password-invalid@seerahpod.local',
            username='mobile_password_invalid',
            auth_provider=User.AuthProvider.EMAIL,
            role=User.Role.USER,
            status=User.Status.ACTIVE,
            password_hash=make_password('User@1234'),
        )
        session = UserSession.objects.create(
            user=user,
            access_token='wc' * 32,
            refresh_token='wr' * 32,
            access_expires_at=timezone.now() + timezone.timedelta(minutes=30),
            refresh_expires_at=timezone.now() + timezone.timedelta(days=30),
        )

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {session.access_token}')
        response = self.client.post(
            '/api/v1/auth/password/change/',
            data={
                'current_password': 'Wrong@1234',
                'new_password': 'User@5678',
                'confirm_password': 'User@5678',
            },
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_password_set_requires_authentication(self):
        response = self.client.post(
            '/api/v1/auth/password/set/',
            data={
                'new_password': 'User@5678',
                'confirm_password': 'User@5678',
            },
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_password_set_for_social_account_rotates_sessions_and_allows_login(self):
        user = User.objects.create(
            email='mobile-password-set@seerahpod.local',
            username='mobile_password_set',
            auth_provider=User.AuthProvider.GOOGLE,
            provider_id='google-sub-2',
            role=User.Role.USER,
            status=User.Status.ACTIVE,
            is_email_verified=True,
        )
        session = UserSession.objects.create(
            user=user,
            access_token='ps' * 32,
            refresh_token='pt' * 32,
            access_expires_at=timezone.now() + timezone.timedelta(minutes=30),
            refresh_expires_at=timezone.now() + timezone.timedelta(days=30),
        )

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {session.access_token}')
        response = self.client.post(
            '/api/v1/auth/password/set/',
            data={
                'new_password': 'User@5678',
                'confirm_password': 'User@5678',
            },
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['ok'])
        self.assertNotEqual(response.data['access_token'], session.access_token)
        self.assertNotEqual(response.data['refresh_token'], session.refresh_token)
        self.assertTrue(response.data['user']['has_password'])

        user.refresh_from_db()
        self.assertTrue(check_password('User@5678', user.password_hash))
        session.refresh_from_db()
        self.assertIsNotNone(session.revoked_at)

        self.client.credentials()
        username_login = self.client.post(
            '/api/v1/auth/login/',
            data={'email': user.username, 'password': 'User@5678'},
            format='json',
        )
        self.assertEqual(username_login.status_code, status.HTTP_200_OK)
        self.assertTrue(username_login.data['ok'])

        email_login = self.client.post(
            '/api/v1/auth/login/',
            data={'email': user.email, 'password': 'User@5678'},
            format='json',
        )
        self.assertEqual(email_login.status_code, status.HTTP_200_OK)
        self.assertTrue(email_login.data['ok'])

    def test_password_set_rejects_when_password_already_exists(self):
        user = User.objects.create(
            email='mobile-password-set-conflict@seerahpod.local',
            username='mobile_password_set_conflict',
            auth_provider=User.AuthProvider.EMAIL,
            role=User.Role.USER,
            status=User.Status.ACTIVE,
            password_hash=make_password('User@1234'),
        )
        session = UserSession.objects.create(
            user=user,
            access_token='pu' * 32,
            refresh_token='pv' * 32,
            access_expires_at=timezone.now() + timezone.timedelta(minutes=30),
            refresh_expires_at=timezone.now() + timezone.timedelta(days=30),
        )

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {session.access_token}')
        response = self.client.post(
            '/api/v1/auth/password/set/',
            data={
                'new_password': 'User@5678',
                'confirm_password': 'User@5678',
            },
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)

    def test_2fa_setup_requires_authentication(self):
        response = self.client.post('/api/v1/auth/2fa/totp/setup/', format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    @override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend')
    def test_2fa_setup_verify_and_login_challenge_flow(self):
        user = User.objects.create(
            email='mobile-2fa@seerahpod.local',
            username='mobile_2fa_user',
            auth_provider=User.AuthProvider.EMAIL,
            role=User.Role.USER,
            status=User.Status.ACTIVE,
            password_hash=make_password('User@1234'),
        )
        session = UserSession.objects.create(
            user=user,
            access_token='2a' * 32,
            refresh_token='2b' * 32,
            access_expires_at=timezone.now() + timezone.timedelta(minutes=30),
            refresh_expires_at=timezone.now() + timezone.timedelta(days=30),
        )
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {session.access_token}')
        mail.outbox.clear()

        setup_response = self.client.post('/api/v1/auth/2fa/totp/setup/', format='json')
        self.assertEqual(setup_response.status_code, status.HTTP_200_OK)
        self.assertTrue(setup_response.data['ok'])
        self.assertEqual(setup_response.data['setup']['delivery'], 'email')
        self.assertTrue(setup_response.data['setup']['email'])
        self.assertTrue(setup_response.data['setup']['message'])
        verify_code = self._latest_email_otp_code()
        self.assertIsNotNone(verify_code)

        verify_response = self.client.post(
            '/api/v1/auth/2fa/totp/verify/',
            data={'code': verify_code},
            format='json',
        )
        self.assertEqual(verify_response.status_code, status.HTTP_200_OK)
        self.assertTrue(verify_response.data['ok'])
        self.assertTrue(verify_response.data['user']['has_2fa_enabled'])
        self.assertEqual(len(verify_response.data['backup_codes']), 10)
        self.assertTrue(UserMfaBackupCode.objects.filter(user=user).exists())
        session.refresh_from_db()
        self.assertIsNotNone(session.revoked_at)

        self.client.credentials()
        login_response = self.client.post(
            '/api/v1/auth/login/',
            data={'email': user.email, 'password': 'User@1234'},
            format='json',
        )
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)
        self.assertTrue(login_response.data['mfa_required'])
        self.assertTrue(login_response.data['mfa_token'])
        self.assertEqual(login_response.data['mfa_delivery'], 'email')
        self.assertTrue(login_response.data['mfa_email'])
        login_code = self._latest_email_otp_code()
        self.assertIsNotNone(login_code)

        login_verify = self.client.post(
            '/api/v1/auth/login/2fa/verify/',
            data={
                'mfa_token': login_response.data['mfa_token'],
                'code': login_code,
            },
            format='json',
        )
        self.assertEqual(login_verify.status_code, status.HTTP_200_OK)
        self.assertTrue(login_verify.data['ok'])
        self.assertFalse(login_verify.data['mfa_required'])
        self.assertIn('access_token', login_verify.data)

    def test_2fa_disable_and_backup_regenerate(self):
        user = User.objects.create(
            email='mobile-2fa-disable@seerahpod.local',
            username='mobile_2fa_disable',
            auth_provider=User.AuthProvider.EMAIL,
            role=User.Role.USER,
            status=User.Status.ACTIVE,
            password_hash=make_password('User@1234'),
        )
        UserMfaTotp.objects.create(
            user=user,
            secret='',
            is_enabled=True,
            verified_at=timezone.now(),
        )
        backup_seed_code = '1234-5678'
        UserMfaBackupCode.objects.create(
            user=user,
            code_hash=make_password('12345678'),
        )
        session = UserSession.objects.create(
            user=user,
            access_token='2c' * 32,
            refresh_token='2d' * 32,
            access_expires_at=timezone.now() + timezone.timedelta(minutes=30),
            refresh_expires_at=timezone.now() + timezone.timedelta(days=30),
        )
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {session.access_token}')

        regen_response = self.client.post(
            '/api/v1/auth/2fa/backup-codes/regenerate/',
            data={
                'current_password': 'User@1234',
                'code': backup_seed_code,
            },
            format='json',
        )
        self.assertEqual(regen_response.status_code, status.HTTP_200_OK)
        self.assertTrue(regen_response.data['ok'])
        self.assertEqual(len(regen_response.data['backup_codes']), 10)
        next_code = regen_response.data['backup_codes'][0]

        disable_response = self.client.post(
            '/api/v1/auth/2fa/totp/disable/',
            data={
                'current_password': 'User@1234',
                'code': next_code,
            },
            format='json',
        )
        self.assertEqual(disable_response.status_code, status.HTTP_200_OK)
        self.assertTrue(disable_response.data['ok'])
        self.assertFalse(disable_response.data['user']['has_2fa_enabled'])
        self.assertFalse(UserMfaBackupCode.objects.filter(user=user).exists())

    def test_revoke_all_sessions_requires_authentication(self):
        response = self.client.post('/api/v1/auth/sessions/revoke-all/', format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_revoke_all_sessions_revokes_current_and_other_user_sessions(self):
        user = User.objects.create(
            email='mobile-revoke-all@seerahpod.local',
            username='mobile_revoke_all',
            auth_provider=User.AuthProvider.EMAIL,
            role=User.Role.USER,
            status=User.Status.ACTIVE,
            password_hash=make_password('User@1234'),
        )
        other_user = User.objects.create(
            email='mobile-revoke-other@seerahpod.local',
            username='mobile_revoke_other',
            auth_provider=User.AuthProvider.EMAIL,
            role=User.Role.USER,
            status=User.Status.ACTIVE,
            password_hash=make_password('User@1234'),
        )

        current = UserSession.objects.create(
            user=user,
            access_token='ra' * 32,
            refresh_token='rb' * 32,
            access_expires_at=timezone.now() + timezone.timedelta(minutes=30),
            refresh_expires_at=timezone.now() + timezone.timedelta(days=30),
        )
        secondary = UserSession.objects.create(
            user=user,
            access_token='rc' * 32,
            refresh_token='rd' * 32,
            access_expires_at=timezone.now() + timezone.timedelta(minutes=30),
            refresh_expires_at=timezone.now() + timezone.timedelta(days=30),
        )
        other = UserSession.objects.create(
            user=other_user,
            access_token='re' * 32,
            refresh_token='rf' * 32,
            access_expires_at=timezone.now() + timezone.timedelta(minutes=30),
            refresh_expires_at=timezone.now() + timezone.timedelta(days=30),
        )

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {current.access_token}')
        response = self.client.post('/api/v1/auth/sessions/revoke-all/', format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['ok'])
        self.assertFalse(response.data['keep_current'])
        self.assertEqual(response.data['revoked_count'], 2)

        current.refresh_from_db()
        secondary.refresh_from_db()
        other.refresh_from_db()
        self.assertIsNotNone(current.revoked_at)
        self.assertIsNotNone(secondary.revoked_at)
        self.assertIsNone(other.revoked_at)

    def test_revoke_all_sessions_can_keep_current(self):
        user = User.objects.create(
            email='mobile-revoke-keep@seerahpod.local',
            username='mobile_revoke_keep',
            auth_provider=User.AuthProvider.EMAIL,
            role=User.Role.USER,
            status=User.Status.ACTIVE,
            password_hash=make_password('User@1234'),
        )
        current = UserSession.objects.create(
            user=user,
            access_token='rk' * 32,
            refresh_token='rl' * 32,
            access_expires_at=timezone.now() + timezone.timedelta(minutes=30),
            refresh_expires_at=timezone.now() + timezone.timedelta(days=30),
        )
        secondary = UserSession.objects.create(
            user=user,
            access_token='rm' * 32,
            refresh_token='rn' * 32,
            access_expires_at=timezone.now() + timezone.timedelta(minutes=30),
            refresh_expires_at=timezone.now() + timezone.timedelta(days=30),
        )

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {current.access_token}')
        response = self.client.post(
            '/api/v1/auth/sessions/revoke-all/',
            data={'keep_current': True},
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['ok'])
        self.assertTrue(response.data['keep_current'])
        self.assertEqual(response.data['revoked_count'], 1)

        current.refresh_from_db()
        secondary.refresh_from_db()
        self.assertIsNone(current.revoked_at)
        self.assertIsNotNone(secondary.revoked_at)

    def test_user_settings_requires_authentication(self):
        response = self.client.get('/api/v1/auth/settings/')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_user_settings_get_creates_default_row(self):
        user = User.objects.create(
            email='mobile-settings@seerahpod.local',
            username='mobile_settings_user',
            auth_provider=User.AuthProvider.EMAIL,
            role=User.Role.USER,
            status=User.Status.ACTIVE,
            password_hash=make_password('User@1234'),
        )
        session = UserSession.objects.create(
            user=user,
            access_token='sg' * 32,
            refresh_token='sr' * 32,
            access_expires_at=timezone.now() + timezone.timedelta(minutes=30),
            refresh_expires_at=timezone.now() + timezone.timedelta(days=30),
        )

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {session.access_token}')
        response = self.client.get('/api/v1/auth/settings/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['ok'])
        self.assertTrue(UserSettings.objects.filter(user=user).exists())
        self.assertEqual(response.data['settings']['playback_speed'], 1.0)
        self.assertTrue(response.data['settings']['auto_play_next'])
        self.assertTrue(response.data['settings']['download_over_wifi_only'])
        self.assertTrue(response.data['settings']['background_play_enabled'])
        self.assertTrue(response.data['settings']['notifications_enabled'])
        self.assertFalse(response.data['settings']['silent_mode'])
        self.assertTrue(response.data['settings']['analytics_enabled'])
        self.assertTrue(response.data['settings']['personalization_enabled'])

    def test_user_settings_patch_updates_values(self):
        user = User.objects.create(
            email='mobile-settings-update@seerahpod.local',
            username='mobile_settings_update',
            auth_provider=User.AuthProvider.EMAIL,
            role=User.Role.USER,
            status=User.Status.ACTIVE,
            password_hash=make_password('User@1234'),
        )
        session = UserSession.objects.create(
            user=user,
            access_token='su' * 32,
            refresh_token='sx' * 32,
            access_expires_at=timezone.now() + timezone.timedelta(minutes=30),
            refresh_expires_at=timezone.now() + timezone.timedelta(days=30),
        )

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {session.access_token}')
        response = self.client.patch(
            '/api/v1/auth/settings/',
            data={
                'playback_speed': 0.25,
                'auto_play_next': False,
                'download_over_wifi_only': False,
                'background_play_enabled': False,
                'notifications_enabled': False,
                'silent_mode': True,
                'analytics_enabled': False,
                'personalization_enabled': False,
            },
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['settings']['playback_speed'], 0.25)
        self.assertFalse(response.data['settings']['auto_play_next'])
        self.assertFalse(response.data['settings']['download_over_wifi_only'])
        self.assertFalse(response.data['settings']['background_play_enabled'])
        self.assertFalse(response.data['settings']['notifications_enabled'])
        self.assertTrue(response.data['settings']['silent_mode'])
        self.assertFalse(response.data['settings']['analytics_enabled'])
        self.assertFalse(response.data['settings']['personalization_enabled'])

        saved = UserSettings.objects.get(user=user)
        self.assertEqual(saved.playback_speed, 0.25)
        self.assertFalse(saved.auto_play_next)
        self.assertFalse(saved.download_over_wifi_only)
        self.assertFalse(saved.background_play_enabled)
        self.assertFalse(saved.notifications_enabled)
        self.assertTrue(saved.silent_mode)
        self.assertFalse(saved.analytics_enabled)
        self.assertFalse(saved.personalization_enabled)

    def test_user_notifications_requires_authentication(self):
        response = self.client.get('/api/v1/auth/notifications/')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_user_notifications_list_returns_user_rows_sorted(self):
        user = User.objects.create(
            email='mobile-notif-list@seerahpod.local',
            username='mobile_notif_list',
            auth_provider=User.AuthProvider.EMAIL,
            role=User.Role.USER,
            status=User.Status.ACTIVE,
            password_hash=make_password('User@1234'),
        )
        other_user = User.objects.create(
            email='mobile-notif-other@seerahpod.local',
            username='mobile_notif_other',
            auth_provider=User.AuthProvider.EMAIL,
            role=User.Role.USER,
            status=User.Status.ACTIVE,
            password_hash=make_password('User@1234'),
        )
        session = UserSession.objects.create(
            user=user,
            access_token='nl' * 32,
            refresh_token='nr' * 32,
            access_expires_at=timezone.now() + timezone.timedelta(minutes=30),
            refresh_expires_at=timezone.now() + timezone.timedelta(days=30),
        )
        older = UserNotification.objects.create(
            user=user,
            notification_type=UserNotification.Type.SYSTEM,
            title='Old',
            message='Old message',
        )
        newer = UserNotification.objects.create(
            user=user,
            notification_type=UserNotification.Type.PODCAST,
            title='New',
            message='New message',
        )
        UserNotification.objects.create(
            user=other_user,
            notification_type=UserNotification.Type.SYSTEM,
            title='Other user',
            message='Must not leak',
        )

        older.read_at = timezone.now()
        older.save(update_fields=['read_at'])

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {session.access_token}')
        response = self.client.get('/api/v1/auth/notifications/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['ok'])
        self.assertEqual(response.data['count'], 2)
        self.assertEqual(response.data['unread_count'], 1)
        self.assertEqual(response.data['results'][0]['id'], str(newer.id))
        self.assertEqual(response.data['results'][1]['id'], str(older.id))

    def test_user_notification_detail_and_mark_read(self):
        user = User.objects.create(
            email='mobile-notif-detail@seerahpod.local',
            username='mobile_notif_detail',
            auth_provider=User.AuthProvider.EMAIL,
            role=User.Role.USER,
            status=User.Status.ACTIVE,
            password_hash=make_password('User@1234'),
        )
        session = UserSession.objects.create(
            user=user,
            access_token='nd' * 32,
            refresh_token='ne' * 32,
            access_expires_at=timezone.now() + timezone.timedelta(minutes=30),
            refresh_expires_at=timezone.now() + timezone.timedelta(days=30),
        )
        row = UserNotification.objects.create(
            user=user,
            notification_type=UserNotification.Type.PREMIUM,
            title='Premium due',
            message='Renew soon',
            action_label='Manage',
            action_route='/profile/subscription',
        )

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {session.access_token}')
        detail_response = self.client.get(f'/api/v1/auth/notifications/{row.id}/')
        self.assertEqual(detail_response.status_code, status.HTTP_200_OK)
        self.assertEqual(detail_response.data['notification']['id'], str(row.id))
        self.assertFalse(detail_response.data['notification']['is_read'])

        patch_response = self.client.patch(
            f'/api/v1/auth/notifications/{row.id}/',
            data={'is_read': True},
            format='json',
        )
        self.assertEqual(patch_response.status_code, status.HTTP_200_OK)
        self.assertTrue(patch_response.data['notification']['is_read'])

        row.refresh_from_db()
        self.assertIsNotNone(row.read_at)

    def test_user_notifications_mark_all_read(self):
        user = User.objects.create(
            email='mobile-notif-all@seerahpod.local',
            username='mobile_notif_all',
            auth_provider=User.AuthProvider.EMAIL,
            role=User.Role.USER,
            status=User.Status.ACTIVE,
            password_hash=make_password('User@1234'),
        )
        session = UserSession.objects.create(
            user=user,
            access_token='ma' * 32,
            refresh_token='mb' * 32,
            access_expires_at=timezone.now() + timezone.timedelta(minutes=30),
            refresh_expires_at=timezone.now() + timezone.timedelta(days=30),
        )
        first = UserNotification.objects.create(
            user=user,
            notification_type=UserNotification.Type.SYSTEM,
            title='A',
            message='A',
        )
        second = UserNotification.objects.create(
            user=user,
            notification_type=UserNotification.Type.RECOMMENDATION,
            title='B',
            message='B',
        )
        second.read_at = timezone.now()
        second.save(update_fields=['read_at'])

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {session.access_token}')
        response = self.client.post('/api/v1/auth/notifications/read-all/', format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['updated_count'], 1)

        first.refresh_from_db()
        second.refresh_from_db()
        self.assertIsNotNone(first.read_at)
        self.assertIsNotNone(second.read_at)

    @override_settings(
        GOOGLE_OAUTH_CLIENT_ID='admin-google-client-id.apps.googleusercontent.com',
        GOOGLE_OAUTH_MOBILE_CLIENT_ID='mobile-google-client-id.apps.googleusercontent.com',
    )
    def test_google_config_endpoint_returns_server_client_id(self):
        response = self.client.get('/api/v1/auth/google/config/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['ok'])
        self.assertEqual(
            response.data['google_server_client_id'],
            'admin-google-client-id.apps.googleusercontent.com',
        )

    def test_home_recently_played_requires_authentication(self):
        response = self.client.get('/api/v1/home/recently-played/')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_home_recently_played_returns_latest_unique_playable_tracks(self):
        user = User.objects.create(
            email='recently-played@seerahpod.local',
            auth_provider=User.AuthProvider.EMAIL,
            role=User.Role.USER,
            status=User.Status.ACTIVE,
            password_hash=make_password('User@1234'),
        )
        session = UserSession.objects.create(
            user=user,
            access_token='rp' * 32,
            refresh_token='rr' * 32,
            access_expires_at=timezone.now() + timezone.timedelta(minutes=30),
            refresh_expires_at=timezone.now() + timezone.timedelta(days=30),
        )

        category = Category.objects.create(name='Recent Category')
        playable_a = Track.objects.create(
            title='Recent A',
            speaker_name='Author A',
            audio_url='https://cdn.example.com/recent-a.mp3',
            cover_image_url='https://cdn.example.com/recent-a.jpg',
            duration_seconds=180,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
            category=category,
        )
        playable_b = Track.objects.create(
            title='Recent B',
            speaker_name='Author B',
            audio_url='https://cdn.example.com/recent-b.mp3',
            cover_image_url='https://cdn.example.com/recent-b.jpg',
            duration_seconds=210,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
            category=category,
        )
        hidden_track = Track.objects.create(
            title='Hidden',
            speaker_name='Hidden',
            audio_url='https://cdn.example.com/hidden.mp3',
            duration_seconds=120,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.HIDDEN,
            category=category,
        )

        old_a = PlayEvent.objects.create(
            user=user,
            track=playable_a,
            played_seconds=40,
            total_duration=180,
            completion_percentage=22.2,
            source=PlayEvent.Source.HOME,
            device_platform=PlayEvent.DevicePlatform.ANDROID,
        )
        latest_a = PlayEvent.objects.create(
            user=user,
            track=playable_a,
            played_seconds=120,
            total_duration=180,
            completion_percentage=66.7,
            source=PlayEvent.Source.HOME,
            device_platform=PlayEvent.DevicePlatform.ANDROID,
        )
        latest_b = PlayEvent.objects.create(
            user=user,
            track=playable_b,
            played_seconds=200,
            total_duration=210,
            completion_percentage=95.2,
            source=PlayEvent.Source.HOME,
            device_platform=PlayEvent.DevicePlatform.ANDROID,
        )
        hidden_event = PlayEvent.objects.create(
            user=user,
            track=hidden_track,
            played_seconds=110,
            total_duration=120,
            completion_percentage=91.6,
            source=PlayEvent.Source.HOME,
            device_platform=PlayEvent.DevicePlatform.ANDROID,
        )

        now = timezone.now()
        PlayEvent.objects.filter(id=old_a.id).update(created_at=now - timezone.timedelta(minutes=30))
        PlayEvent.objects.filter(id=latest_a.id).update(created_at=now - timezone.timedelta(minutes=10))
        PlayEvent.objects.filter(id=latest_b.id).update(created_at=now - timezone.timedelta(minutes=5))
        PlayEvent.objects.filter(id=hidden_event.id).update(created_at=now - timezone.timedelta(minutes=1))

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {session.access_token}')
        response = self.client.get('/api/v1/home/recently-played/?limit=10')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['ok'])
        self.assertEqual(response.data['count'], 2)
        self.assertEqual(
            [row['id'] for row in response.data['results']],
            [str(playable_b.id), str(playable_a.id)],
        )
        self.assertEqual(response.data['results'][0]['progress_percent'], 95.2)
        self.assertEqual(response.data['results'][1]['progress_percent'], 66.7)

    def test_play_event_requires_authentication(self):
        response = self.client.post(
            '/api/v1/play-events/',
            data={'track_id': '00000000-0000-0000-0000-000000000000'},
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_play_event_creates_row_for_authenticated_user(self):
        user = User.objects.create(
            email='play-event@seerahpod.local',
            auth_provider=User.AuthProvider.EMAIL,
            role=User.Role.USER,
            status=User.Status.ACTIVE,
            password_hash=make_password('User@1234'),
        )
        session = UserSession.objects.create(
            user=user,
            access_token='pe' * 32,
            refresh_token='pr' * 32,
            access_expires_at=timezone.now() + timezone.timedelta(minutes=30),
            refresh_expires_at=timezone.now() + timezone.timedelta(days=30),
        )
        category = Category.objects.create(name='Play Event Category')
        track = Track.objects.create(
            title='Track For Event',
            speaker_name='Speaker',
            audio_url='https://cdn.example.com/track-for-event.mp3',
            duration_seconds=240,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
            category=category,
        )

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {session.access_token}')
        response = self.client.post(
            '/api/v1/play-events/',
            data={
                'track_id': str(track.id),
                'played_seconds': 48,
                'total_duration': 240,
                'source': PlayEvent.Source.SEARCH,
            },
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(response.data['ok'])
        self.assertEqual(PlayEvent.objects.count(), 1)
        created = PlayEvent.objects.first()
        self.assertIsNotNone(created)
        self.assertEqual(created.user_id, user.id)
        self.assertEqual(created.track_id, track.id)
        self.assertEqual(created.played_seconds, 48)
        self.assertEqual(created.total_duration, 240)
        self.assertAlmostEqual(created.completion_percentage, 20.0, places=3)
        self.assertEqual(created.source, PlayEvent.Source.SEARCH)
        self.assertEqual(created.device_platform, PlayEvent.DevicePlatform.ANDROID)

    def test_home_continue_listening_requires_authentication(self):
        response = self.client.get('/api/v1/home/continue-listening/')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_home_continue_listening_returns_latest_unique_tracks_in_progress_window(self):
        user = User.objects.create(
            email='continue-listening@seerahpod.local',
            auth_provider=User.AuthProvider.EMAIL,
            role=User.Role.USER,
            status=User.Status.ACTIVE,
            password_hash=make_password('User@1234'),
        )
        session = UserSession.objects.create(
            user=user,
            access_token='cl' * 32,
            refresh_token='cr' * 32,
            access_expires_at=timezone.now() + timezone.timedelta(minutes=30),
            refresh_expires_at=timezone.now() + timezone.timedelta(days=30),
        )
        category = Category.objects.create(name='Continue Listening')
        track_a = Track.objects.create(
            title='Continue A',
            speaker_name='Speaker A',
            audio_url='https://cdn.example.com/continue-a.mp3',
            duration_seconds=200,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
            category=category,
        )
        track_b = Track.objects.create(
            title='Continue B',
            speaker_name='Speaker B',
            audio_url='https://cdn.example.com/continue-b.mp3',
            duration_seconds=240,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
            category=category,
        )
        track_c = Track.objects.create(
            title='Continue C',
            speaker_name='Speaker C',
            audio_url='https://cdn.example.com/continue-c.mp3',
            duration_seconds=260,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
            category=category,
        )
        hidden_track = Track.objects.create(
            title='Hidden',
            speaker_name='Hidden',
            audio_url='https://cdn.example.com/hidden-continue.mp3',
            duration_seconds=180,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.HIDDEN,
            category=category,
        )

        old_a = PlayEvent.objects.create(
            user=user,
            track=track_a,
            played_seconds=50,
            total_duration=200,
            completion_percentage=25.0,
            source=PlayEvent.Source.HOME,
            device_platform=PlayEvent.DevicePlatform.ANDROID,
        )
        latest_a = PlayEvent.objects.create(
            user=user,
            track=track_a,
            played_seconds=90,
            total_duration=200,
            completion_percentage=45.0,
            source=PlayEvent.Source.HOME,
            device_platform=PlayEvent.DevicePlatform.ANDROID,
        )
        completed_b = PlayEvent.objects.create(
            user=user,
            track=track_b,
            played_seconds=240,
            total_duration=240,
            completion_percentage=100.0,
            source=PlayEvent.Source.HOME,
            device_platform=PlayEvent.DevicePlatform.ANDROID,
        )
        in_progress_c = PlayEvent.objects.create(
            user=user,
            track=track_c,
            played_seconds=52,
            total_duration=260,
            completion_percentage=20.0,
            source=PlayEvent.Source.HOME,
            device_platform=PlayEvent.DevicePlatform.ANDROID,
        )
        hidden_event = PlayEvent.objects.create(
            user=user,
            track=hidden_track,
            played_seconds=40,
            total_duration=180,
            completion_percentage=22.2,
            source=PlayEvent.Source.HOME,
            device_platform=PlayEvent.DevicePlatform.ANDROID,
        )

        now = timezone.now()
        PlayEvent.objects.filter(id=old_a.id).update(created_at=now - timezone.timedelta(minutes=25))
        PlayEvent.objects.filter(id=latest_a.id).update(created_at=now - timezone.timedelta(minutes=10))
        PlayEvent.objects.filter(id=completed_b.id).update(created_at=now - timezone.timedelta(minutes=8))
        PlayEvent.objects.filter(id=in_progress_c.id).update(created_at=now - timezone.timedelta(minutes=5))
        PlayEvent.objects.filter(id=hidden_event.id).update(created_at=now - timezone.timedelta(minutes=3))

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {session.access_token}')
        response = self.client.get('/api/v1/home/continue-listening/?limit=5')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['ok'])
        self.assertEqual(response.data['count'], 2)
        self.assertEqual(
            [row['id'] for row in response.data['results']],
            [str(track_c.id), str(track_a.id)],
        )
        self.assertEqual(response.data['results'][0]['progress_percent'], 20.0)
        self.assertEqual(response.data['results'][1]['progress_percent'], 45.0)


class AdminTrackViewsTests(APITestCase):
    def setUp(self):
        self.client.defaults['HTTP_HOST'] = 'localhost'
        self.admin_user = User.objects.create(
            email='admin-tests@seerahpod.local',
            auth_provider=User.AuthProvider.EMAIL,
            role=User.Role.ADMIN,
            status=User.Status.ACTIVE,
            password_hash=make_password('Admin@123'),
        )
        self.admin_session = AdminSession.objects.create(
            user=self.admin_user,
            access_token='a' * 64,
            refresh_token='r' * 64,
            access_expires_at=timezone.now() + timezone.timedelta(minutes=30),
            refresh_expires_at=timezone.now() + timezone.timedelta(days=30),
        )
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.admin_session.access_token}')

    def test_create_track(self):
        payload = {
            'title': 'Journey to Madinah',
            'speaker_name': 'Sheikh Umar',
            'description': 'Key moments from Hijrah.',
            'audio_url': 'https://cdn.example.com/journey-to-madinah.mp3',
            'cover_image_url': 'https://cdn.example.com/journey-cover.jpg',
            'duration_seconds': 1850,
            'category_name': 'Seerah',
            'is_premium': True,
            'visibility': 'public',
        }

        response = self.client.post('/api/v1/admin/content/tracks/', data=payload, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(response.data['ok'])
        self.assertEqual(response.data['track']['title'], payload['title'])
        self.assertEqual(response.data['track']['category']['name'], 'Seerah')
        self.assertEqual(Track.objects.count(), 1)

    def test_list_tracks_omits_soft_deleted(self):
        active_track = Track.objects.create(
            title='Active Track',
            speaker_name='Speaker One',
            audio_url='https://cdn.example.com/active.mp3',
            duration_seconds=100,
        )
        deleted_track = Track.objects.create(
            title='Deleted Track',
            speaker_name='Speaker Two',
            audio_url='https://cdn.example.com/deleted.mp3',
            duration_seconds=120,
        )
        deleted_track.deleted_at = timezone.now()
        deleted_track.save(update_fields=['deleted_at', 'updated_at'])

        response = self.client.get('/api/v1/admin/content/tracks/')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['ok'])
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(response.data['results'][0]['id'], str(active_track.id))

    def test_publish_and_soft_delete_track(self):
        track = Track.objects.create(
            title='Draft Track',
            speaker_name='Speaker',
            audio_url='https://cdn.example.com/draft.mp3',
            duration_seconds=321,
            status=Track.Status.DRAFT,
        )

        publish_response = self.client.post(f'/api/v1/admin/content/tracks/{track.id}/publish/', format='json')
        self.assertEqual(publish_response.status_code, status.HTTP_200_OK)
        track.refresh_from_db()
        self.assertEqual(track.status, Track.Status.PUBLISHED)

        delete_response = self.client.delete(f'/api/v1/admin/content/tracks/{track.id}/')
        self.assertEqual(delete_response.status_code, status.HTTP_204_NO_CONTENT)
        track.refresh_from_db()
        self.assertIsNotNone(track.deleted_at)

    def test_create_track_with_multiple_cover_images(self):
        audio = SimpleUploadedFile('sample.mp3', b'ID3FAKEAUDIO', content_type='audio/mpeg')
        cover_1 = SimpleUploadedFile('cover-1.jpg', b'FAKEIMG1', content_type='image/jpeg')
        cover_2 = SimpleUploadedFile('cover-2.jpg', b'FAKEIMG2', content_type='image/jpeg')

        payload = {
            'title': 'Multi Cover Track',
            'speaker_name': 'Uploader',
            'duration_seconds': '60',
            'audio_file': audio,
            'cover_image_files': [cover_1, cover_2],
        }

        response = self.client.post('/api/v1/admin/content/tracks/', data=payload, format='multipart')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(response.data['ok'])
        self.assertEqual(len(response.data['track']['cover_images']), 2)
        track_id = response.data['track']['id']
        self.assertEqual(TrackCoverImage.objects.filter(track_id=track_id).count(), 2)

    def test_list_and_create_categories(self):
        Category.objects.create(name='Old Category')

        list_response = self.client.get('/api/v1/admin/content/categories/')
        self.assertEqual(list_response.status_code, status.HTTP_200_OK)
        self.assertTrue(list_response.data['ok'])
        self.assertGreaterEqual(list_response.data['count'], 1)

        create_response = self.client.post(
            '/api/v1/admin/content/categories/',
            data={'name': 'Podcast'},
            format='json',
        )
        self.assertEqual(create_response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(create_response.data['ok'])
        self.assertEqual(create_response.data['category']['name'], 'Podcast')
        self.assertTrue(Category.objects.filter(name='Podcast').exists())

    def test_delete_category(self):
        category = Category.objects.create(name='Temporary Category')
        response = self.client.delete(f'/api/v1/admin/content/categories/{category.id}/')
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Category.objects.filter(id=category.id).exists())

    def test_list_and_create_playlists(self):
        Playlist.objects.create(title='History Playlist', visibility='public')

        list_response = self.client.get('/api/v1/admin/playlists/')
        self.assertEqual(list_response.status_code, status.HTTP_200_OK)
        self.assertTrue(list_response.data['ok'])
        self.assertGreaterEqual(list_response.data['count'], 1)

        create_response = self.client.post(
            '/api/v1/admin/playlists/',
            data={'title': 'Premium Stories', 'visibility': 'premium'},
            format='json',
        )
        self.assertEqual(create_response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(create_response.data['ok'])
        self.assertEqual(create_response.data['playlist']['title'], 'Premium Stories')
        created_playlist_id = create_response.data['playlist']['id']
        self.assertTrue(
            AdminAuditLog.objects.filter(
                admin=self.admin_user,
                action='playlist.create',
                entity_type='playlist',
                entity_id=created_playlist_id,
            ).exists()
        )

    def test_list_recommendation_rules_seeds_defaults(self):
        response = self.client.get('/api/v1/admin/recommendations/rules/')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['ok'])
        self.assertEqual(response.data['count'], 3)
        self.assertEqual(
            [row['rule_key'] for row in response.data['results']],
            ['top_played', 'recently_added', 'based_on_history'],
        )
        self.assertEqual(
            [row['priority'] for row in response.data['results']],
            [1, 2, 3],
        )

    def test_toggle_recommendation_rule(self):
        rule = RecommendationRule.objects.create(
            rule_key='top_played',
            name='Top Played',
            description='desc',
            priority=1,
            is_active=True,
            config={'days': 7, 'limit': 10},
        )

        deactivate_response = self.client.post(f'/api/v1/admin/recommendations/rules/{rule.id}/deactivate/', format='json')
        self.assertEqual(deactivate_response.status_code, status.HTTP_200_OK)
        rule.refresh_from_db()
        self.assertFalse(rule.is_active)
        self.assertTrue(
            AdminAuditLog.objects.filter(
                admin=self.admin_user,
                action='recommendation_rule.deactivate',
                entity_type='recommendation_rule',
                entity_id=rule.id,
            ).exists()
        )

        activate_response = self.client.post(f'/api/v1/admin/recommendations/rules/{rule.id}/activate/', format='json')
        self.assertEqual(activate_response.status_code, status.HTTP_200_OK)
        rule.refresh_from_db()
        self.assertTrue(rule.is_active)
        self.assertTrue(
            AdminAuditLog.objects.filter(
                admin=self.admin_user,
                action='recommendation_rule.activate',
                entity_type='recommendation_rule',
                entity_id=rule.id,
            ).exists()
        )

    def test_reorder_recommendation_rules(self):
        first = RecommendationRule.objects.create(
            rule_key='top_played',
            name='Top Played',
            description='desc',
            priority=1,
            is_active=True,
        )
        second = RecommendationRule.objects.create(
            rule_key='recently_added',
            name='Recently Added',
            description='desc',
            priority=2,
            is_active=True,
        )
        third = RecommendationRule.objects.create(
            rule_key='based_on_history',
            name='Based on History',
            description='desc',
            priority=3,
            is_active=True,
        )

        response = self.client.post(
            '/api/v1/admin/recommendations/reorder/',
            data={'rule_ids': [str(second.id), str(first.id), str(third.id)]},
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual([row['id'] for row in response.data['results']], [str(second.id), str(first.id), str(third.id)])

        second.refresh_from_db()
        first.refresh_from_db()
        third.refresh_from_db()
        self.assertEqual(second.priority, 1)
        self.assertEqual(first.priority, 2)
        self.assertEqual(third.priority, 3)

    def test_runtime_recommendations_recently_added_only_last_two_days(self):
        RecommendationRule.objects.create(
            rule_key='recently_added',
            name='Recently Added',
            description='Recent tracks',
            priority=1,
            is_active=True,
            config={'days': 2, 'limit': 10},
        )

        recent_track = Track.objects.create(
            title='Recent Track',
            speaker_name='Speaker',
            audio_url='https://cdn.example.com/recent.mp3',
            duration_seconds=180,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
        )
        old_track = Track.objects.create(
            title='Old Track',
            speaker_name='Speaker',
            audio_url='https://cdn.example.com/old.mp3',
            duration_seconds=180,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
        )
        draft_track = Track.objects.create(
            title='Draft Recent Track',
            speaker_name='Speaker',
            audio_url='https://cdn.example.com/draft.mp3',
            duration_seconds=180,
            status=Track.Status.DRAFT,
            visibility=Track.Visibility.PUBLIC,
        )

        Track.objects.filter(id=recent_track.id).update(created_at=timezone.now() - timezone.timedelta(days=1))
        Track.objects.filter(id=old_track.id).update(created_at=timezone.now() - timezone.timedelta(days=3))
        Track.objects.filter(id=draft_track.id).update(created_at=timezone.now() - timezone.timedelta(hours=6))

        response = self.client.get('/api/v1/recommendations/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['ok'])
        self.assertEqual(response.data['count'], 1)

        section = response.data['results'][0]
        self.assertEqual(section['rule_key'], 'recently_added')
        self.assertEqual(section['track_count'], 1)
        self.assertEqual(section['tracks'][0]['id'], str(recent_track.id))

    def test_runtime_recommendations_top_played_orders_by_usage(self):
        RecommendationRule.objects.create(
            rule_key='top_played',
            name='Top Played',
            description='Most played tracks',
            priority=1,
            is_active=True,
            config={'days': 7, 'limit': 2},
        )

        listener = User.objects.create(
            email='listener@example.com',
            auth_provider=User.AuthProvider.EMAIL,
        )

        top_track = Track.objects.create(
            title='Top Track',
            speaker_name='Speaker',
            audio_url='https://cdn.example.com/top.mp3',
            duration_seconds=300,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
        )
        second_track = Track.objects.create(
            title='Second Track',
            speaker_name='Speaker',
            audio_url='https://cdn.example.com/second.mp3',
            duration_seconds=300,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
        )
        old_window_track = Track.objects.create(
            title='Old Window Track',
            speaker_name='Speaker',
            audio_url='https://cdn.example.com/old-window.mp3',
            duration_seconds=300,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
        )
        hidden_track = Track.objects.create(
            title='Hidden Track',
            speaker_name='Speaker',
            audio_url='https://cdn.example.com/hidden.mp3',
            duration_seconds=300,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.HIDDEN,
        )

        PlayEvent.objects.bulk_create(
            [
                PlayEvent(
                    user=listener,
                    track=top_track,
                    played_seconds=220,
                    total_duration=300,
                    completion_percentage=73.3,
                    source=PlayEvent.Source.HOME,
                    device_platform=PlayEvent.DevicePlatform.ANDROID,
                ),
                PlayEvent(
                    user=listener,
                    track=top_track,
                    played_seconds=200,
                    total_duration=300,
                    completion_percentage=66.6,
                    source=PlayEvent.Source.HOME,
                    device_platform=PlayEvent.DevicePlatform.ANDROID,
                ),
                PlayEvent(
                    user=listener,
                    track=second_track,
                    played_seconds=180,
                    total_duration=300,
                    completion_percentage=60.0,
                    source=PlayEvent.Source.HOME,
                    device_platform=PlayEvent.DevicePlatform.ANDROID,
                ),
                PlayEvent(
                    user=listener,
                    track=old_window_track,
                    played_seconds=250,
                    total_duration=300,
                    completion_percentage=83.3,
                    source=PlayEvent.Source.HOME,
                    device_platform=PlayEvent.DevicePlatform.ANDROID,
                ),
                PlayEvent(
                    user=listener,
                    track=hidden_track,
                    played_seconds=260,
                    total_duration=300,
                    completion_percentage=86.6,
                    source=PlayEvent.Source.HOME,
                    device_platform=PlayEvent.DevicePlatform.ANDROID,
                ),
            ]
        )

        PlayEvent.objects.filter(track_id=old_window_track.id).update(
            created_at=timezone.now() - timezone.timedelta(days=10)
        )

        response = self.client.get('/api/v1/recommendations/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['ok'])
        self.assertEqual(response.data['count'], 1)

        section = response.data['results'][0]
        self.assertEqual(section['rule_key'], 'top_played')
        self.assertEqual(section['track_count'], 2)
        self.assertEqual(
            [row['id'] for row in section['tracks']],
            [str(top_track.id), str(second_track.id)],
        )

    def test_runtime_recommendations_based_on_history_for_user(self):
        RecommendationRule.objects.all().delete()
        RecommendationRule.objects.create(
            rule_key='based_on_history',
            name='Based on History',
            description='Personalized by category affinity',
            priority=1,
            is_active=True,
            config={'days': 30, 'min_listens': 2, 'limit': 3, 'top_categories': 2},
        )

        listener = User.objects.create(
            email='history-listener@example.com',
            auth_provider=User.AuthProvider.EMAIL,
        )
        other_user = User.objects.create(
            email='history-other@example.com',
            auth_provider=User.AuthProvider.EMAIL,
        )

        cat_a = Category.objects.create(name='History Cat A')
        cat_b = Category.objects.create(name='History Cat B')

        cat_a_track_personal = Track.objects.create(
            title='A Personal Track',
            speaker_name='Speaker A',
            audio_url='https://cdn.example.com/a1.mp3',
            duration_seconds=200,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
            category=cat_a,
        )
        cat_a_track_popular = Track.objects.create(
            title='A Popular Track',
            speaker_name='Speaker A',
            audio_url='https://cdn.example.com/a2.mp3',
            duration_seconds=210,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
            category=cat_a,
        )
        cat_b_track = Track.objects.create(
            title='B Track',
            speaker_name='Speaker B',
            audio_url='https://cdn.example.com/b1.mp3',
            duration_seconds=220,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
            category=cat_b,
        )

        PlayEvent.objects.bulk_create(
            [
                PlayEvent(
                    user=listener,
                    track=cat_a_track_personal,
                    played_seconds=180,
                    total_duration=200,
                    completion_percentage=90.0,
                    source=PlayEvent.Source.HOME,
                    device_platform=PlayEvent.DevicePlatform.ANDROID,
                ),
                PlayEvent(
                    user=listener,
                    track=cat_a_track_personal,
                    played_seconds=170,
                    total_duration=200,
                    completion_percentage=85.0,
                    source=PlayEvent.Source.HOME,
                    device_platform=PlayEvent.DevicePlatform.ANDROID,
                ),
                PlayEvent(
                    user=listener,
                    track=cat_b_track,
                    played_seconds=120,
                    total_duration=220,
                    completion_percentage=54.5,
                    source=PlayEvent.Source.HOME,
                    device_platform=PlayEvent.DevicePlatform.ANDROID,
                ),
                PlayEvent(
                    user=other_user,
                    track=cat_a_track_popular,
                    played_seconds=200,
                    total_duration=210,
                    completion_percentage=95.2,
                    source=PlayEvent.Source.HOME,
                    device_platform=PlayEvent.DevicePlatform.ANDROID,
                ),
                PlayEvent(
                    user=other_user,
                    track=cat_a_track_popular,
                    played_seconds=200,
                    total_duration=210,
                    completion_percentage=95.2,
                    source=PlayEvent.Source.HOME,
                    device_platform=PlayEvent.DevicePlatform.ANDROID,
                ),
            ]
        )

        response = self.client.get(f'/api/v1/recommendations/?user_id={listener.id}')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['ok'])
        self.assertEqual(response.data['count'], 1)

        section = response.data['results'][0]
        self.assertEqual(section['rule_key'], 'based_on_history')
        self.assertGreaterEqual(section['track_count'], 2)
        self.assertEqual(
            [row['id'] for row in section['tracks'][:2]],
            [str(cat_a_track_popular.id), str(cat_a_track_personal.id)],
        )

    def test_trending_podcasts_returns_ranked_podcast_tracks(self):
        podcast_category, _ = Category.objects.get_or_create(name='Podcast')
        lecture_category, _ = Category.objects.get_or_create(name='Lecture')

        trending_top = Track.objects.create(
            title='Top Podcast',
            speaker_name='Host A',
            audio_url='https://cdn.example.com/top-podcast.mp3',
            duration_seconds=300,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
            category=podcast_category,
        )
        trending_second = Track.objects.create(
            title='Second Podcast',
            speaker_name='Host B',
            audio_url='https://cdn.example.com/second-podcast.mp3',
            duration_seconds=280,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
            category=podcast_category,
        )
        hidden_podcast = Track.objects.create(
            title='Hidden Podcast',
            speaker_name='Host C',
            audio_url='https://cdn.example.com/hidden-podcast.mp3',
            duration_seconds=260,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.HIDDEN,
            category=podcast_category,
        )
        non_podcast = Track.objects.create(
            title='Lecture Audio',
            speaker_name='Scholar',
            audio_url='https://cdn.example.com/lecture.mp3',
            duration_seconds=400,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
            category=lecture_category,
        )

        PlayEvent.objects.bulk_create(
            [
                PlayEvent(
                    user=self.admin_user,
                    track=trending_top,
                    played_seconds=220,
                    total_duration=300,
                    completion_percentage=73.3,
                    source=PlayEvent.Source.HOME,
                    device_platform=PlayEvent.DevicePlatform.ANDROID,
                ),
                PlayEvent(
                    user=self.admin_user,
                    track=trending_top,
                    played_seconds=210,
                    total_duration=300,
                    completion_percentage=70.0,
                    source=PlayEvent.Source.HOME,
                    device_platform=PlayEvent.DevicePlatform.ANDROID,
                ),
                PlayEvent(
                    user=self.admin_user,
                    track=trending_second,
                    played_seconds=180,
                    total_duration=280,
                    completion_percentage=64.2,
                    source=PlayEvent.Source.HOME,
                    device_platform=PlayEvent.DevicePlatform.ANDROID,
                ),
                PlayEvent(
                    user=self.admin_user,
                    track=hidden_podcast,
                    played_seconds=250,
                    total_duration=260,
                    completion_percentage=96.1,
                    source=PlayEvent.Source.HOME,
                    device_platform=PlayEvent.DevicePlatform.ANDROID,
                ),
                PlayEvent(
                    user=self.admin_user,
                    track=non_podcast,
                    played_seconds=320,
                    total_duration=400,
                    completion_percentage=80.0,
                    source=PlayEvent.Source.HOME,
                    device_platform=PlayEvent.DevicePlatform.ANDROID,
                ),
            ]
        )

        response = self.client.get('/api/v1/trending/podcasts/?days=30&limit=5')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['ok'])
        self.assertEqual(response.data['count'], 2)
        self.assertEqual(
            [row['id'] for row in response.data['results']],
            [str(trending_top.id), str(trending_second.id)],
        )

    def test_search_tracks_returns_published_public_matches(self):
        category = Category.objects.create(name='Song')

        match = Track.objects.create(
            title='Noor Anthem',
            speaker_name='Artist A',
            audio_url='https://cdn.example.com/noor.mp3',
            duration_seconds=210,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
            category=category,
        )
        Track.objects.create(
            title='Noor Draft',
            speaker_name='Artist B',
            audio_url='https://cdn.example.com/noor-draft.mp3',
            duration_seconds=200,
            status=Track.Status.DRAFT,
            visibility=Track.Visibility.PUBLIC,
            category=category,
        )
        Track.objects.create(
            title='Noor Hidden',
            speaker_name='Artist C',
            audio_url='https://cdn.example.com/noor-hidden.mp3',
            duration_seconds=190,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.HIDDEN,
            category=category,
        )
        deleted = Track.objects.create(
            title='Noor Deleted',
            speaker_name='Artist D',
            audio_url='https://cdn.example.com/noor-deleted.mp3',
            duration_seconds=180,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
            category=category,
        )
        deleted.deleted_at = timezone.now()
        deleted.save(update_fields=['deleted_at', 'updated_at'])

        response = self.client.get('/api/v1/search/tracks/?q=noor&limit=10')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['ok'])
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(response.data['results'][0]['id'], str(match.id))
        self.assertEqual(SearchLog.objects.count(), 1)
        search_log = SearchLog.objects.first()
        self.assertIsNotNone(search_log)
        self.assertIsNone(search_log.user)
        self.assertEqual(search_log.query, 'noor')
        self.assertEqual(search_log.normalized_query, 'noor')
        self.assertEqual(search_log.result_count, 1)
        self.assertEqual(search_log.source_screen, SearchLog.SourceScreen.SEARCH_PAGE)
        self.assertEqual(search_log.device_platform, SearchLog.DevicePlatform.ANDROID)

    def test_search_tracks_creates_log_for_authenticated_user(self):
        category = Category.objects.create(name='Search User Category')
        Track.objects.create(
            title='Faith Song',
            speaker_name='Artist',
            audio_url='https://cdn.example.com/faith.mp3',
            duration_seconds=180,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
            category=category,
        )
        user = User.objects.create(
            email='search-logger@seerahpod.local',
            auth_provider=User.AuthProvider.EMAIL,
            role=User.Role.USER,
            status=User.Status.ACTIVE,
        )
        session = UserSession.objects.create(
            user=user,
            access_token='u' * 64,
            refresh_token='v' * 64,
            access_expires_at=timezone.now() + timezone.timedelta(minutes=30),
            refresh_expires_at=timezone.now() + timezone.timedelta(days=7),
        )
        self.client.credentials(
            HTTP_AUTHORIZATION=f'Bearer {session.access_token}',
            HTTP_USER_AGENT='SeerahPod/1.0 (Android)',
        )

        response = self.client.get('/api/v1/search/tracks/?q=faith&limit=10&source_screen=home')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(SearchLog.objects.count(), 1)
        search_log = SearchLog.objects.first()
        self.assertIsNotNone(search_log)
        self.assertEqual(search_log.user_id, user.id)
        self.assertEqual(search_log.query, 'faith')
        self.assertEqual(search_log.normalized_query, 'faith')
        self.assertEqual(search_log.result_count, 1)
        self.assertEqual(search_log.source_screen, SearchLog.SourceScreen.HOME)
        self.assertEqual(search_log.device_platform, SearchLog.DevicePlatform.ANDROID)

    def test_search_suggestions_returns_queries_above_threshold(self):
        SearchLog.objects.bulk_create(
            [
                SearchLog(
                    query='Noor',
                    normalized_query='noor',
                    result_count=3,
                    source_screen=SearchLog.SourceScreen.SEARCH_PAGE,
                    device_platform=SearchLog.DevicePlatform.ANDROID,
                )
                for _ in range(120)
            ]
            + [
                SearchLog(
                    query='Seerah',
                    normalized_query='seerah',
                    result_count=2,
                    source_screen=SearchLog.SourceScreen.SEARCH_PAGE,
                    device_platform=SearchLog.DevicePlatform.ANDROID,
                )
                for _ in range(101)
            ]
            + [
                SearchLog(
                    query='Low volume',
                    normalized_query='low volume',
                    result_count=1,
                    source_screen=SearchLog.SourceScreen.SEARCH_PAGE,
                    device_platform=SearchLog.DevicePlatform.ANDROID,
                )
                for _ in range(99)
            ]
            + [
                SearchLog(
                    query='Edge case',
                    normalized_query='edge case',
                    result_count=1,
                    source_screen=SearchLog.SourceScreen.SEARCH_PAGE,
                    device_platform=SearchLog.DevicePlatform.ANDROID,
                )
                for _ in range(100)
            ]
        )

        response = self.client.get('/api/v1/search/suggestions/?min_count=100&limit=10')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['ok'])
        self.assertEqual(response.data['count'], 2)
        self.assertEqual(
            [row['query'] for row in response.data['results']],
            ['noor', 'seerah'],
        )
        self.assertEqual(
            [row['search_count'] for row in response.data['results']],
            [120, 101],
        )

    def test_public_playlists_returns_recent_visible_active_playlists(self):
        track = Track.objects.create(
            title='Playlist Track',
            speaker_name='Speaker',
            audio_url='https://cdn.example.com/playlist-track.mp3',
            cover_image_url='https://cdn.example.com/playlist-track.jpg',
            duration_seconds=180,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
        )
        second_track = Track.objects.create(
            title='Playlist Track 2',
            speaker_name='Speaker',
            audio_url='https://cdn.example.com/playlist-track-2.mp3',
            cover_image_url='https://cdn.example.com/playlist-track-2.jpg',
            duration_seconds=181,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
        )
        older = Playlist.objects.create(
            title='Older Playlist',
            visibility=Playlist.Visibility.PUBLIC,
            is_active=True,
        )
        newer = Playlist.objects.create(
            title='Newer Playlist',
            visibility=Playlist.Visibility.PREMIUM,
            is_active=True,
        )
        hidden = Playlist.objects.create(
            title='Hidden Playlist',
            visibility=Playlist.Visibility.HIDDEN,
            is_active=True,
        )
        inactive = Playlist.objects.create(
            title='Inactive Playlist',
            visibility=Playlist.Visibility.PUBLIC,
            is_active=False,
        )
        deleted = Playlist.objects.create(
            title='Deleted Playlist',
            visibility=Playlist.Visibility.PUBLIC,
            is_active=True,
        )

        PlaylistTrack.objects.create(playlist=older, track=track, position=1)
        PlaylistTrack.objects.create(playlist=newer, track=track, position=1)
        PlaylistTrack.objects.create(playlist=newer, track=second_track, position=2)

        now = timezone.now()
        Playlist.objects.filter(id=older.id).update(created_at=now - timezone.timedelta(days=2))
        Playlist.objects.filter(id=newer.id).update(created_at=now - timezone.timedelta(days=1))
        Playlist.objects.filter(id=hidden.id).update(created_at=now - timezone.timedelta(hours=12))
        Playlist.objects.filter(id=inactive.id).update(created_at=now - timezone.timedelta(hours=10))
        Playlist.objects.filter(id=deleted.id).update(
            created_at=now - timezone.timedelta(hours=8),
            deleted_at=now - timezone.timedelta(hours=7),
        )

        response = self.client.get('/api/v1/playlists/?limit=10')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['ok'])
        self.assertEqual(response.data['count'], 2)
        self.assertEqual(
            [row['id'] for row in response.data['results']],
            [str(newer.id), str(older.id)],
        )
        self.assertEqual(response.data['results'][0]['track_count'], 2)
        self.assertEqual(response.data['results'][1]['track_count'], 1)
        self.assertEqual(
            response.data['results'][0]['preview_cover_image_urls'],
            [
                'https://cdn.example.com/playlist-track.jpg',
                'https://cdn.example.com/playlist-track-2.jpg',
            ],
        )
        self.assertEqual(
            response.data['results'][1]['preview_cover_image_urls'],
            ['https://cdn.example.com/playlist-track.jpg'],
        )
        self.assertEqual(response.data['total_count'], 2)
        self.assertEqual(response.data['offset'], 0)
        self.assertEqual(response.data['limit'], 10)
        self.assertFalse(response.data['has_more'])
        self.assertIsNone(response.data['next_offset'])

    def test_public_playlists_supports_offset_pagination(self):
        track = Track.objects.create(
            title='Paginated Playlist Track',
            speaker_name='Speaker',
            audio_url='https://cdn.example.com/paginated-playlist-track.mp3',
            duration_seconds=180,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
        )
        first = Playlist.objects.create(
            title='Pagination First',
            visibility=Playlist.Visibility.PUBLIC,
            is_active=True,
        )
        second = Playlist.objects.create(
            title='Pagination Second',
            visibility=Playlist.Visibility.PUBLIC,
            is_active=True,
        )
        third = Playlist.objects.create(
            title='Pagination Third',
            visibility=Playlist.Visibility.PUBLIC,
            is_active=True,
        )
        PlaylistTrack.objects.create(playlist=first, track=track, position=1)
        PlaylistTrack.objects.create(playlist=second, track=track, position=1)
        PlaylistTrack.objects.create(playlist=third, track=track, position=1)

        now = timezone.now()
        Playlist.objects.filter(id=first.id).update(created_at=now - timezone.timedelta(days=3))
        Playlist.objects.filter(id=second.id).update(created_at=now - timezone.timedelta(days=2))
        Playlist.objects.filter(id=third.id).update(created_at=now - timezone.timedelta(days=1))

        response = self.client.get('/api/v1/playlists/?limit=1&offset=1')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['ok'])
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(response.data['total_count'], 3)
        self.assertEqual(response.data['offset'], 1)
        self.assertEqual(response.data['limit'], 1)
        self.assertTrue(response.data['has_more'])
        self.assertEqual(response.data['next_offset'], 2)
        self.assertEqual(response.data['results'][0]['id'], str(second.id))

    def test_public_playlists_supports_query_filter(self):
        track = Track.objects.create(
            title='Searchable Playlist Track',
            speaker_name='Speaker',
            audio_url='https://cdn.example.com/searchable-playlist-track.mp3',
            duration_seconds=180,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
        )
        matching = Playlist.objects.create(
            title='Morning Dhikr Collection',
            description='Daily morning and evening athkar.',
            visibility=Playlist.Visibility.PUBLIC,
            is_active=True,
        )
        other = Playlist.objects.create(
            title='Stories for Sleep',
            description='Relaxed storytelling mix.',
            visibility=Playlist.Visibility.PUBLIC,
            is_active=True,
        )
        PlaylistTrack.objects.create(playlist=matching, track=track, position=1)
        PlaylistTrack.objects.create(playlist=other, track=track, position=1)

        response = self.client.get('/api/v1/playlists/?limit=10&q=dhikr')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['ok'])
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(response.data['total_count'], 1)
        self.assertEqual(response.data['results'][0]['id'], str(matching.id))

    def test_playlist_click_creates_event_with_authenticated_user(self):
        user = User.objects.create(
            email='playlist-click@seerahpod.local',
            auth_provider=User.AuthProvider.EMAIL,
            role=User.Role.USER,
            status=User.Status.ACTIVE,
            password_hash=make_password('User@1234'),
        )
        session = UserSession.objects.create(
            user=user,
            access_token='pc' * 32,
            refresh_token='pr' * 32,
            access_expires_at=timezone.now() + timezone.timedelta(minutes=30),
            refresh_expires_at=timezone.now() + timezone.timedelta(days=30),
        )
        playlist = Playlist.objects.create(
            title='Clicked Playlist',
            visibility=Playlist.Visibility.PUBLIC,
            is_active=True,
        )

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {session.access_token}')
        response = self.client.post(
            f'/api/v1/playlists/{playlist.id}/click/',
            data={'source': PlaylistClickEvent.Source.LIBRARY},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(response.data['ok'])
        self.assertEqual(PlaylistClickEvent.objects.count(), 1)
        event = PlaylistClickEvent.objects.first()
        self.assertIsNotNone(event)
        self.assertEqual(event.playlist_id, playlist.id)
        self.assertEqual(event.user_id, user.id)
        self.assertEqual(event.source, PlaylistClickEvent.Source.LIBRARY)
        self.assertEqual(event.device_platform, PlaylistClickEvent.DevicePlatform.ANDROID)

    def test_top_playlists_returns_only_clicked_playlists_ranked_by_clicks(self):
        first_track = Track.objects.create(
            title='First Top Track',
            speaker_name='Speaker',
            audio_url='https://cdn.example.com/first-top.mp3',
            cover_image_url='https://cdn.example.com/first-top.jpg',
            duration_seconds=180,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
        )
        second_track = Track.objects.create(
            title='Second Top Track',
            speaker_name='Speaker',
            audio_url='https://cdn.example.com/second-top.mp3',
            cover_image_url='https://cdn.example.com/second-top.jpg',
            duration_seconds=180,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
        )
        third_track = Track.objects.create(
            title='Third Top Track',
            speaker_name='Speaker',
            audio_url='https://cdn.example.com/third-top.mp3',
            cover_image_url='https://cdn.example.com/third-top.jpg',
            duration_seconds=180,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
        )
        first = Playlist.objects.create(
            title='First Playlist',
            visibility=Playlist.Visibility.PUBLIC,
            is_active=True,
        )
        second = Playlist.objects.create(
            title='Second Playlist',
            visibility=Playlist.Visibility.PREMIUM,
            is_active=True,
        )
        old_only = Playlist.objects.create(
            title='Old Click Playlist',
            visibility=Playlist.Visibility.PUBLIC,
            is_active=True,
        )
        hidden = Playlist.objects.create(
            title='Hidden Click Playlist',
            visibility=Playlist.Visibility.HIDDEN,
            is_active=True,
        )

        PlaylistTrack.objects.create(playlist=first, track=first_track, position=1)
        PlaylistTrack.objects.create(playlist=second, track=second_track, position=1)
        PlaylistTrack.objects.create(playlist=old_only, track=third_track, position=1)
        PlaylistTrack.objects.create(playlist=hidden, track=first_track, position=1)

        now = timezone.now()
        first_events = [
            PlaylistClickEvent.objects.create(
                playlist=first,
                source=PlaylistClickEvent.Source.LIBRARY,
                device_platform=PlaylistClickEvent.DevicePlatform.ANDROID,
            )
            for _ in range(2)
        ]
        second_events = [
            PlaylistClickEvent.objects.create(
                playlist=second,
                source=PlaylistClickEvent.Source.LIBRARY,
                device_platform=PlaylistClickEvent.DevicePlatform.ANDROID,
            )
            for _ in range(3)
        ]
        old_event = PlaylistClickEvent.objects.create(
            playlist=old_only,
            source=PlaylistClickEvent.Source.LIBRARY,
            device_platform=PlaylistClickEvent.DevicePlatform.ANDROID,
        )
        hidden_event = PlaylistClickEvent.objects.create(
            playlist=hidden,
            source=PlaylistClickEvent.Source.LIBRARY,
            device_platform=PlaylistClickEvent.DevicePlatform.ANDROID,
        )
        for idx, event in enumerate(first_events):
            PlaylistClickEvent.objects.filter(id=event.id).update(
                created_at=now - timezone.timedelta(days=4, minutes=idx),
            )
        for idx, event in enumerate(second_events):
            PlaylistClickEvent.objects.filter(id=event.id).update(
                created_at=now - timezone.timedelta(days=1, minutes=idx),
            )
        PlaylistClickEvent.objects.filter(id=old_event.id).update(
            created_at=now - timezone.timedelta(days=45),
        )
        PlaylistClickEvent.objects.filter(id=hidden_event.id).update(
            created_at=now - timezone.timedelta(days=1),
        )

        response = self.client.get('/api/v1/playlists/top/?window_days=30&limit=10')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['ok'])
        self.assertEqual(response.data['count'], 2)
        self.assertEqual(
            [row['id'] for row in response.data['results']],
            [str(second.id), str(first.id)],
        )
        self.assertEqual(
            [row['click_count'] for row in response.data['results']],
            [3, 2],
        )

    def test_user_track_like_endpoint_supports_like_and_unlike(self):
        user = User.objects.create(
            email='like-user@seerahpod.local',
            username='like-user',
            auth_provider=User.AuthProvider.EMAIL,
            status=User.Status.ACTIVE,
            password_hash=make_password('User@1234'),
        )
        session = UserSession.objects.create(
            user=user,
            access_token='lk' * 32,
            refresh_token='lr' * 32,
            access_expires_at=timezone.now() + timezone.timedelta(minutes=30),
            refresh_expires_at=timezone.now() + timezone.timedelta(days=30),
        )
        track = Track.objects.create(
            title='Likable Track',
            speaker_name='Artist',
            audio_url='https://cdn.example.com/likable.mp3',
            duration_seconds=180,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
        )
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {session.access_token}')

        initial = self.client.get(f'/api/v1/auth/tracks/{track.id}/like/')
        self.assertEqual(initial.status_code, status.HTTP_200_OK)
        self.assertFalse(initial.data['is_liked'])

        like_response = self.client.post(
            f'/api/v1/auth/tracks/{track.id}/like/',
            data={'is_liked': True},
            format='json',
        )
        self.assertEqual(like_response.status_code, status.HTTP_200_OK)
        self.assertTrue(like_response.data['is_liked'])
        self.assertTrue(UserTrackLike.objects.filter(user=user, track=track).exists())

        duplicate_like_response = self.client.post(
            f'/api/v1/auth/tracks/{track.id}/like/',
            data={'is_liked': True},
            format='json',
        )
        self.assertEqual(duplicate_like_response.status_code, status.HTTP_200_OK)
        self.assertEqual(UserTrackLike.objects.filter(user=user, track=track).count(), 1)

        unlike_response = self.client.post(
            f'/api/v1/auth/tracks/{track.id}/like/',
            data={'is_liked': False},
            format='json',
        )
        self.assertEqual(unlike_response.status_code, status.HTTP_200_OK)
        self.assertFalse(unlike_response.data['is_liked'])
        self.assertFalse(UserTrackLike.objects.filter(user=user, track=track).exists())

    def test_top_playlists_includes_liked_songs_for_authenticated_user(self):
        user = User.objects.create(
            email='liked-playlists-user@seerahpod.local',
            username='liked-playlists-user',
            auth_provider=User.AuthProvider.EMAIL,
            status=User.Status.ACTIVE,
            password_hash=make_password('User@1234'),
        )
        session = UserSession.objects.create(
            user=user,
            access_token='tl' * 32,
            refresh_token='tr' * 32,
            access_expires_at=timezone.now() + timezone.timedelta(minutes=30),
            refresh_expires_at=timezone.now() + timezone.timedelta(days=30),
        )
        liked_track = Track.objects.create(
            title='Liked In Top',
            speaker_name='Artist',
            audio_url='https://cdn.example.com/liked-in-top.mp3',
            cover_image_url='https://cdn.example.com/liked-in-top.jpg',
            duration_seconds=180,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
        )
        UserTrackLike.objects.create(user=user, track=liked_track)

        top_track = Track.objects.create(
            title='Top Click Track',
            speaker_name='Artist',
            audio_url='https://cdn.example.com/top-click-track.mp3',
            duration_seconds=180,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
        )
        clicked_playlist = Playlist.objects.create(
            title='Clicked Playlist',
            visibility=Playlist.Visibility.PUBLIC,
            is_active=True,
        )
        PlaylistTrack.objects.create(playlist=clicked_playlist, track=top_track, position=1)
        PlaylistClickEvent.objects.create(
            playlist=clicked_playlist,
            user=user,
            source=PlaylistClickEvent.Source.LIBRARY,
            device_platform=PlaylistClickEvent.DevicePlatform.ANDROID,
        )

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {session.access_token}')
        response = self.client.get('/api/v1/playlists/top/?window_days=30&limit=10')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['ok'])
        self.assertGreaterEqual(response.data['count'], 1)
        self.assertEqual(
            response.data['results'][0]['id'],
            '00000000-0000-0000-0000-00000000f00d',
        )
        self.assertEqual(response.data['results'][0]['title'], 'Liked Songs')
        self.assertEqual(response.data['results'][0]['track_count'], 1)

    def test_liked_songs_playlist_tracks_requires_auth_and_returns_liked_tracks(self):
        liked_playlist_id = '00000000-0000-0000-0000-00000000f00d'
        user = User.objects.create(
            email='liked-tracks-user@seerahpod.local',
            username='liked-tracks-user',
            auth_provider=User.AuthProvider.EMAIL,
            status=User.Status.ACTIVE,
            password_hash=make_password('User@1234'),
        )
        session = UserSession.objects.create(
            user=user,
            access_token='lt' * 32,
            refresh_token='ls' * 32,
            access_expires_at=timezone.now() + timezone.timedelta(minutes=30),
            refresh_expires_at=timezone.now() + timezone.timedelta(days=30),
        )
        older_track = Track.objects.create(
            title='Older Liked',
            speaker_name='Artist',
            audio_url='https://cdn.example.com/older-liked.mp3',
            cover_image_url='https://cdn.example.com/older-liked.jpg',
            duration_seconds=180,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
        )
        newer_track = Track.objects.create(
            title='Newer Liked',
            speaker_name='Artist',
            audio_url='https://cdn.example.com/newer-liked.mp3',
            cover_image_url='https://cdn.example.com/newer-liked.jpg',
            duration_seconds=180,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
        )

        older_like = UserTrackLike.objects.create(user=user, track=older_track)
        newer_like = UserTrackLike.objects.create(user=user, track=newer_track)
        now = timezone.now()
        UserTrackLike.objects.filter(id=older_like.id).update(
            created_at=now - timezone.timedelta(days=2),
        )
        UserTrackLike.objects.filter(id=newer_like.id).update(
            created_at=now - timezone.timedelta(days=1),
        )

        unauthenticated = self.client.get(f'/api/v1/playlists/{liked_playlist_id}/tracks/')
        self.assertEqual(unauthenticated.status_code, status.HTTP_401_UNAUTHORIZED)

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {session.access_token}')
        response = self.client.get(f'/api/v1/playlists/{liked_playlist_id}/tracks/')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['ok'])
        self.assertEqual(response.data['playlist']['id'], liked_playlist_id)
        self.assertEqual(response.data['playlist']['title'], 'Liked Songs')
        self.assertEqual(response.data['count'], 2)
        self.assertEqual(
            [row['id'] for row in response.data['results']],
            [str(newer_track.id), str(older_track.id)],
        )

    def test_public_playlist_tracks_returns_playable_tracks_in_position_order(self):
        playlist = Playlist.objects.create(
            title='Public Playlist',
            visibility=Playlist.Visibility.PUBLIC,
            is_active=True,
        )
        playable_two = Track.objects.create(
            title='Playable Two',
            speaker_name='Speaker',
            audio_url='https://cdn.example.com/playable-two.mp3',
            cover_image_url='https://cdn.example.com/playable-two.jpg',
            duration_seconds=210,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
        )
        playable_one = Track.objects.create(
            title='Playable One',
            speaker_name='Speaker',
            audio_url='https://cdn.example.com/playable-one.mp3',
            cover_image_url='https://cdn.example.com/playable-one.jpg',
            duration_seconds=200,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
        )
        hidden_track = Track.objects.create(
            title='Hidden Track',
            speaker_name='Speaker',
            audio_url='https://cdn.example.com/hidden-track.mp3',
            duration_seconds=199,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.HIDDEN,
        )

        PlaylistTrack.objects.create(playlist=playlist, track=playable_two, position=2)
        PlaylistTrack.objects.create(playlist=playlist, track=playable_one, position=1)
        PlaylistTrack.objects.create(playlist=playlist, track=hidden_track, position=0)

        response = self.client.get(f'/api/v1/playlists/{playlist.id}/tracks/')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['ok'])
        self.assertEqual(response.data['playlist']['id'], str(playlist.id))
        self.assertEqual(response.data['count'], 2)
        self.assertEqual(
            [row['id'] for row in response.data['results']],
            [str(playable_one.id), str(playable_two.id)],
        )
        self.assertEqual(
            response.data['playlist']['preview_cover_image_urls'],
            [
                'https://cdn.example.com/playable-one.jpg',
                'https://cdn.example.com/playable-two.jpg',
            ],
        )

    def test_library_podcasts_returns_only_podcast_tracks_with_pagination(self):
        podcast = Category.objects.create(name='Podcast')
        music = Category.objects.create(name='Music')
        podcast_track_old = Track.objects.create(
            title='Podcast Old',
            speaker_name='Host',
            audio_url='https://cdn.example.com/podcast-old.mp3',
            duration_seconds=180,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
            category=podcast,
        )
        podcast_track_new = Track.objects.create(
            title='Podcast New',
            speaker_name='Host',
            audio_url='https://cdn.example.com/podcast-new.mp3',
            duration_seconds=200,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
            category=podcast,
        )
        Track.objects.create(
            title='Song Track',
            speaker_name='Artist',
            audio_url='https://cdn.example.com/song-track.mp3',
            duration_seconds=190,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
            category=music,
        )

        now = timezone.now()
        Track.objects.filter(id=podcast_track_old.id).update(
            created_at=now - timezone.timedelta(days=2),
        )
        Track.objects.filter(id=podcast_track_new.id).update(
            created_at=now - timezone.timedelta(days=1),
        )

        response = self.client.get('/api/v1/library/podcasts/?limit=1&offset=0')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['ok'])
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(response.data['total_count'], 2)
        self.assertTrue(response.data['has_more'])
        self.assertEqual(response.data['next_offset'], 1)
        self.assertEqual(response.data['results'][0]['id'], str(podcast_track_new.id))

    def test_library_songs_excludes_podcast_tracks_with_pagination(self):
        podcast = Category.objects.create(name='Podcast')
        music = Category.objects.create(name='Music')
        Track.objects.create(
            title='Podcast Track',
            speaker_name='Host',
            audio_url='https://cdn.example.com/podcast-only.mp3',
            duration_seconds=180,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
            category=podcast,
        )
        song_old = Track.objects.create(
            title='Song Old',
            speaker_name='Artist',
            audio_url='https://cdn.example.com/song-old.mp3',
            duration_seconds=210,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
            category=music,
        )
        song_new = Track.objects.create(
            title='Song New',
            speaker_name='Artist',
            audio_url='https://cdn.example.com/song-new.mp3',
            duration_seconds=220,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
            category=None,
        )

        now = timezone.now()
        Track.objects.filter(id=song_old.id).update(
            created_at=now - timezone.timedelta(days=2),
        )
        Track.objects.filter(id=song_new.id).update(
            created_at=now - timezone.timedelta(days=1),
        )

        response = self.client.get('/api/v1/library/songs/?limit=1&offset=0')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['ok'])
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(response.data['total_count'], 2)
        self.assertTrue(response.data['has_more'])
        self.assertEqual(response.data['next_offset'], 1)
        self.assertEqual(response.data['results'][0]['id'], str(song_new.id))

    def test_public_categories_list_returns_only_playable_categories(self):
        playable = Category.objects.create(name='Playable Category')
        empty = Category.objects.create(name='Empty Category')

        Track.objects.create(
            title='Playable Track',
            speaker_name='Artist',
            audio_url='https://cdn.example.com/playable.mp3',
            duration_seconds=200,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
            category=playable,
        )
        Track.objects.create(
            title='Hidden Track',
            speaker_name='Artist',
            audio_url='https://cdn.example.com/hidden.mp3',
            duration_seconds=200,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.HIDDEN,
            category=empty,
        )

        response = self.client.get('/api/v1/categories/')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['ok'])
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(response.data['results'][0]['id'], str(playable.id))
        self.assertEqual(response.data['results'][0]['track_count'], 1)

    def test_public_category_tracks_returns_only_playable_tracks(self):
        category = Category.objects.create(name='Nasheed')

        playable = Track.objects.create(
            title='Play Me',
            speaker_name='Artist',
            audio_url='https://cdn.example.com/play-me.mp3',
            duration_seconds=190,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
            category=category,
        )
        Track.objects.create(
            title='Draft Me',
            speaker_name='Artist',
            audio_url='https://cdn.example.com/draft-me.mp3',
            duration_seconds=190,
            status=Track.Status.DRAFT,
            visibility=Track.Visibility.PUBLIC,
            category=category,
        )
        Track.objects.create(
            title='Hidden Me',
            speaker_name='Artist',
            audio_url='https://cdn.example.com/hidden-me.mp3',
            duration_seconds=190,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.HIDDEN,
            category=category,
        )

        response = self.client.get(f'/api/v1/categories/{category.id}/tracks/?limit=20')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['ok'])
        self.assertEqual(response.data['category']['id'], str(category.id))
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(response.data['total_count'], 1)
        self.assertFalse(response.data['has_more'])
        self.assertIsNone(response.data['next_offset'])
        self.assertEqual(response.data['results'][0]['id'], str(playable.id))

    def test_public_category_tracks_supports_offset_pagination(self):
        category = Category.objects.create(name='Pagination Category')

        t1 = Track.objects.create(
            title='Track One',
            speaker_name='Artist',
            audio_url='https://cdn.example.com/t1.mp3',
            duration_seconds=120,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
            category=category,
        )
        t2 = Track.objects.create(
            title='Track Two',
            speaker_name='Artist',
            audio_url='https://cdn.example.com/t2.mp3',
            duration_seconds=120,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
            category=category,
        )
        t3 = Track.objects.create(
            title='Track Three',
            speaker_name='Artist',
            audio_url='https://cdn.example.com/t3.mp3',
            duration_seconds=120,
            status=Track.Status.PUBLISHED,
            visibility=Track.Visibility.PUBLIC,
            category=category,
        )

        now = timezone.now()
        Track.objects.filter(id=t1.id).update(created_at=now - timezone.timedelta(minutes=3))
        Track.objects.filter(id=t2.id).update(created_at=now - timezone.timedelta(minutes=2))
        Track.objects.filter(id=t3.id).update(created_at=now - timezone.timedelta(minutes=1))

        response = self.client.get(f'/api/v1/categories/{category.id}/tracks/?limit=1&offset=1')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['ok'])
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(response.data['total_count'], 3)
        self.assertEqual(response.data['offset'], 1)
        self.assertEqual(response.data['limit'], 1)
        self.assertTrue(response.data['has_more'])
        self.assertEqual(response.data['next_offset'], 2)
        self.assertEqual(response.data['results'][0]['id'], str(t2.id))


class SupportChatApiTests(APITestCase):
    def setUp(self):
        self.client.defaults['HTTP_HOST'] = 'localhost'
        self.user = User.objects.create(
            email='support-user@seerahpod.local',
            username='support_user',
            auth_provider=User.AuthProvider.EMAIL,
            role=User.Role.USER,
            status=User.Status.ACTIVE,
            password_hash=make_password('User@1234'),
        )
        self.other_user = User.objects.create(
            email='support-other@seerahpod.local',
            username='support_other',
            auth_provider=User.AuthProvider.EMAIL,
            role=User.Role.USER,
            status=User.Status.ACTIVE,
            password_hash=make_password('User@1234'),
        )
        self.admin_user = User.objects.create(
            email='support-admin@seerahpod.local',
            username='support_admin',
            auth_provider=User.AuthProvider.EMAIL,
            role=User.Role.ADMIN,
            status=User.Status.ACTIVE,
            password_hash=make_password('Admin@123'),
        )
        self.user_session = UserSession.objects.create(
            user=self.user,
            access_token=('ua' * 32),
            refresh_token=('ur' * 32),
            access_expires_at=timezone.now() + timezone.timedelta(minutes=30),
            refresh_expires_at=timezone.now() + timezone.timedelta(days=30),
        )
        self.admin_session = AdminSession.objects.create(
            user=self.admin_user,
            access_token=('aa' * 32),
            refresh_token=('ar' * 32),
            access_expires_at=timezone.now() + timezone.timedelta(minutes=30),
            refresh_expires_at=timezone.now() + timezone.timedelta(days=30),
        )

    def _as_user(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.user_session.access_token}')

    def _as_admin(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.admin_session.access_token}')

    def test_user_open_creates_and_reuses_active_ticket(self):
        self._as_user()

        first = self.client.post('/api/v1/auth/support/tickets/open/', format='json')
        self.assertEqual(first.status_code, status.HTTP_201_CREATED)
        self.assertTrue(first.data['created'])
        ticket_id = first.data['ticket']['id']

        second = self.client.post('/api/v1/auth/support/tickets/open/', format='json')
        self.assertEqual(second.status_code, status.HTTP_200_OK)
        self.assertFalse(second.data['created'])
        self.assertEqual(second.data['ticket']['id'], ticket_id)
        self.assertEqual(SupportTicket.objects.filter(user=self.user).count(), 1)

    def test_user_messages_for_other_users_ticket_are_blocked(self):
        ticket = SupportTicket.objects.create(
            user=self.other_user,
            subject='Other user ticket',
            status=SupportTicket.Status.OPEN,
        )
        self._as_user()

        response = self.client.get(f'/api/v1/auth/support/tickets/{ticket.id}/messages/')
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_user_send_message_is_idempotent_and_updates_admin_unread(self):
        ticket = SupportTicket.objects.create(
            user=self.user,
            subject='Need help',
            status=SupportTicket.Status.OPEN,
        )
        self._as_user()

        first = self.client.post(
            f'/api/v1/auth/support/tickets/{ticket.id}/messages/',
            data={
                'message': 'Cannot play downloaded tracks.',
                'client_message_id': 'mob-1',
            },
            format='json',
        )
        self.assertEqual(first.status_code, status.HTTP_201_CREATED)
        self.assertTrue(first.data['created'])
        first_message_id = first.data['message']['id']

        ticket.refresh_from_db()
        self.assertEqual(ticket.admin_unread_count, 1)
        self.assertIsNotNone(ticket.last_message_at)
        self.assertEqual(SupportMessage.objects.filter(ticket=ticket).count(), 1)

        second = self.client.post(
            f'/api/v1/auth/support/tickets/{ticket.id}/messages/',
            data={
                'message': 'Cannot play downloaded tracks.',
                'client_message_id': 'mob-1',
            },
            format='json',
        )
        self.assertEqual(second.status_code, status.HTTP_200_OK)
        self.assertFalse(second.data['created'])
        self.assertEqual(second.data['message']['id'], first_message_id)
        self.assertEqual(SupportMessage.objects.filter(ticket=ticket).count(), 1)

        ticket.refresh_from_db()
        self.assertEqual(ticket.admin_unread_count, 1)

    def test_user_send_message_to_closed_ticket_returns_ticket_closed_code(self):
        ticket = SupportTicket.objects.create(
            user=self.user,
            subject='Closed ticket',
            status=SupportTicket.Status.CLOSED,
            closed_at=timezone.now(),
        )
        self._as_user()

        response = self.client.post(
            f'/api/v1/auth/support/tickets/{ticket.id}/messages/',
            data={'message': 'Please reopen this'},
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(response.data['code'], 'ticket_closed')
        self.assertEqual(response.data['next_action'], 'open_new_ticket')

    def test_user_summary_and_mark_read_flow(self):
        ticket = SupportTicket.objects.create(
            user=self.user,
            subject='Unread from admin',
            status=SupportTicket.Status.OPEN,
            user_unread_count=2,
        )
        self._as_user()

        summary = self.client.get('/api/v1/auth/support/summary/')
        self.assertEqual(summary.status_code, status.HTTP_200_OK)
        self.assertEqual(summary.data['active_ticket_id'], str(ticket.id))
        self.assertEqual(summary.data['unread_message_count'], 2)
        self.assertTrue(summary.data['has_unread'])

        read_response = self.client.post(f'/api/v1/auth/support/tickets/{ticket.id}/read/', format='json')
        self.assertEqual(read_response.status_code, status.HTTP_200_OK)
        self.assertEqual(read_response.data['ticket']['user_unread_count'], 0)

        summary_after = self.client.get('/api/v1/auth/support/summary/')
        self.assertEqual(summary_after.status_code, status.HTTP_200_OK)
        self.assertEqual(summary_after.data['unread_message_count'], 0)
        self.assertFalse(summary_after.data['has_unread'])

    def test_admin_reply_and_mark_read_update_counters(self):
        ticket = SupportTicket.objects.create(
            user=self.user,
            subject='Admin reply flow',
            status=SupportTicket.Status.OPEN,
            admin_unread_count=2,
        )
        self._as_admin()

        reply = self.client.post(
            f'/api/v1/admin/support/tickets/{ticket.id}/messages/',
            data={
                'message': 'Please update your app to the latest version.',
                'client_message_id': 'adm-1',
            },
            format='json',
        )
        self.assertEqual(reply.status_code, status.HTTP_201_CREATED)
        self.assertTrue(reply.data['created'])
        self.assertEqual(reply.data['message']['sender_type'], SupportMessage.SenderType.ADMIN)

        ticket.refresh_from_db()
        self.assertEqual(ticket.user_unread_count, 1)

        mark_read = self.client.post(f'/api/v1/admin/support/tickets/{ticket.id}/read/', format='json')
        self.assertEqual(mark_read.status_code, status.HTTP_200_OK)
        ticket.refresh_from_db()
        self.assertEqual(ticket.admin_unread_count, 0)

    def test_admin_assign_status_and_summary(self):
        first = SupportTicket.objects.create(
            user=self.user,
            subject='Assignment target',
            status=SupportTicket.Status.OPEN,
            admin_unread_count=0,
        )
        second = SupportTicket.objects.create(
            user=self.other_user,
            subject='In progress ticket',
            status=SupportTicket.Status.IN_PROGRESS,
            admin_unread_count=3,
        )
        self._as_admin()

        assign = self.client.post(
            f'/api/v1/admin/support/tickets/{first.id}/assign/',
            data={'admin_id': str(self.admin_user.id)},
            format='json',
        )
        self.assertEqual(assign.status_code, status.HTTP_200_OK)
        self.assertEqual(assign.data['ticket']['assigned_admin']['id'], str(self.admin_user.id))

        status_update = self.client.post(
            f'/api/v1/admin/support/tickets/{first.id}/status/',
            data={'status': SupportTicket.Status.CLOSED},
            format='json',
        )
        self.assertEqual(status_update.status_code, status.HTTP_200_OK)
        self.assertEqual(status_update.data['ticket']['status'], SupportTicket.Status.CLOSED)
        self.assertIsNotNone(status_update.data['ticket']['closed_at'])

        summary = self.client.get('/api/v1/admin/support/summary/')
        self.assertEqual(summary.status_code, status.HTTP_200_OK)
        self.assertEqual(summary.data['open_count'], 0)
        self.assertEqual(summary.data['in_progress_count'], 1)
        self.assertEqual(summary.data['unread_ticket_count'], 1)
        self.assertEqual(summary.data['unread_message_count'], 3)

        filtered = self.client.get('/api/v1/admin/support/tickets/?status=in_progress')
        self.assertEqual(filtered.status_code, status.HTTP_200_OK)
        self.assertEqual(filtered.data['count'], 1)
        self.assertEqual(filtered.data['results'][0]['id'], str(second.id))
