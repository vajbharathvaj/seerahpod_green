from django.urls import path

from . import admin_insights, admin_v1, views

urlpatterns = [
    path('health/', views.HealthView.as_view(), name='health'),
    path('v1/platform/config/', views.PublicPlatformConfigView.as_view(), name='v1-platform-config'),
    path('v1/auth/signup/', views.UserAuthSignupView.as_view(), name='v1-user-auth-signup'),
    path('v1/auth/login/', views.UserAuthLoginView.as_view(), name='v1-user-auth-login'),
    path('v1/auth/google/config/', views.UserAuthGoogleConfigView.as_view(), name='v1-user-auth-google-config'),
    path('v1/auth/google/', views.UserAuthGoogleView.as_view(), name='v1-user-auth-google'),
    path('v1/auth/refresh/', views.UserAuthRefreshView.as_view(), name='v1-user-auth-refresh'),
    path('v1/auth/logout/', views.UserAuthLogoutView.as_view(), name='v1-user-auth-logout'),
    path('v1/auth/sessions/revoke-all/', views.UserAuthSessionsRevokeAllView.as_view(), name='v1-user-auth-sessions-revoke-all'),
    path('v1/auth/me/', views.UserAuthMeView.as_view(), name='v1-user-auth-me'),
    path('v1/auth/password/change/', views.UserAuthPasswordChangeView.as_view(), name='v1-user-auth-password-change'),
    path('v1/auth/password/set/', views.UserAuthPasswordSetView.as_view(), name='v1-user-auth-password-set'),
    path('v1/auth/login/2fa/verify/', views.UserAuthLogin2FAVerifyView.as_view(), name='v1-user-auth-login-2fa-verify'),
    path('v1/auth/2fa/totp/setup/', views.UserAuth2FATotpSetupView.as_view(), name='v1-user-auth-2fa-totp-setup'),
    path('v1/auth/2fa/totp/verify/', views.UserAuth2FATotpVerifyView.as_view(), name='v1-user-auth-2fa-totp-verify'),
    path('v1/auth/2fa/totp/disable/', views.UserAuth2FATotpDisableView.as_view(), name='v1-user-auth-2fa-totp-disable'),
    path('v1/auth/2fa/backup-codes/regenerate/', views.UserAuth2FABackupCodesRegenerateView.as_view(), name='v1-user-auth-2fa-backup-codes-regenerate'),
    path('v1/auth/settings/', views.UserAuthSettingsView.as_view(), name='v1-user-auth-settings'),
    path('v1/auth/notifications/', views.UserAuthNotificationsView.as_view(), name='v1-user-auth-notifications'),
    path('v1/auth/notifications/read-all/', views.UserAuthNotificationsMarkAllReadView.as_view(), name='v1-user-auth-notifications-read-all'),
    path('v1/auth/notifications/<uuid:id>/', views.UserAuthNotificationDetailView.as_view(), name='v1-user-auth-notification-detail'),
    path('v1/auth/tracks/<uuid:id>/like/', views.UserTrackLikeView.as_view(), name='v1-user-track-like'),
    path('v1/auth/support/tickets/open/', views.UserSupportTicketOpenView.as_view(), name='v1-user-support-ticket-open'),
    path('v1/auth/support/tickets/me/active/', views.UserSupportTicketActiveView.as_view(), name='v1-user-support-ticket-active'),
    path('v1/auth/support/tickets/<uuid:id>/messages/', views.UserSupportTicketMessagesView.as_view(), name='v1-user-support-ticket-messages'),
    path('v1/auth/support/tickets/<uuid:id>/read/', views.UserSupportTicketReadView.as_view(), name='v1-user-support-ticket-read'),
    path('v1/auth/support/summary/', views.UserSupportSummaryView.as_view(), name='v1-user-support-summary'),
    path('v1/categories/', views.CategoriesListView.as_view(), name='v1-categories'),
    path('v1/categories/<uuid:id>/tracks/', views.CategoryTracksView.as_view(), name='v1-category-tracks'),
    path('v1/playlists/', views.PlaylistsListView.as_view(), name='v1-playlists'),
    path('v1/playlists/top/', views.TopPlaylistsView.as_view(), name='v1-top-playlists'),
    path('v1/playlists/<uuid:id>/click/', views.PlaylistClickCreateView.as_view(), name='v1-playlist-click'),
    path('v1/playlists/<uuid:id>/tracks/', views.PlaylistTracksView.as_view(), name='v1-playlist-tracks'),
    path('v1/library/podcasts/', views.LibraryPodcastsTracksView.as_view(), name='v1-library-podcasts'),
    path('v1/library/songs/', views.LibrarySongsTracksView.as_view(), name='v1-library-songs'),
    path('v1/search/tracks/', views.SearchTracksView.as_view(), name='v1-search-tracks'),
    path('v1/search/suggestions/', views.SearchSuggestionsView.as_view(), name='v1-search-suggestions'),
    path('v1/play-events/', views.PlayEventCreateView.as_view(), name='v1-play-events-create'),
    path('v1/home/continue-listening/', views.HomeContinueListeningView.as_view(), name='v1-home-continue-listening'),
    path('v1/home/recently-played/', views.HomeRecentlyPlayedView.as_view(), name='v1-home-recently-played'),
    path('v1/recommendations/', views.RecommendationsFeedView.as_view(), name='v1-recommendations-feed'),
    path('v1/trending/podcasts/', views.TrendingPodcastsView.as_view(), name='v1-trending-podcasts'),
    path('v1/recommendations/stats/', views.RecommendationStatsView.as_view(), name='v1-recommendations-stats'),
    path('admin/insights/summary/', admin_insights.SummaryView.as_view(), name='insights-summary'),
    path('admin/insights/premium-conversions/', admin_insights.PremiumConversionsView.as_view(), name='insights-premium-conversions'),
    path('admin/insights/conversion-funnel/', admin_insights.ConversionFunnelView.as_view(), name='insights-conversion-funnel'),

    # v1 admin base: /api/v1/admin/
    # 1) Auth
    path('v1/admin/auth/login/', admin_v1.AdminAuthLoginView.as_view(), name='v1-admin-auth-login'),
    path('v1/admin/auth/google/', admin_v1.AdminAuthGoogleView.as_view(), name='v1-admin-auth-google'),
    path('v1/admin/auth/logout/', admin_v1.AdminAuthLogoutView.as_view(), name='v1-admin-auth-logout'),
    path('v1/admin/auth/me/', admin_v1.AdminAuthMeView.as_view(), name='v1-admin-auth-me'),
    path('v1/admin/auth/refresh/', admin_v1.AdminAuthRefreshView.as_view(), name='v1-admin-auth-refresh'),

    # 2) Audio content management
    path('v1/admin/content/tracks/', admin_v1.AdminTracksCollectionView.as_view(), name='v1-admin-content-tracks'),
    path('v1/admin/content/tracks/<uuid:id>/', admin_v1.AdminTrackDetailView.as_view(), name='v1-admin-content-track-detail'),
    path('v1/admin/content/tracks/<uuid:id>/publish/', admin_v1.AdminTrackPublishView.as_view(), name='v1-admin-content-track-publish'),
    path('v1/admin/content/tracks/<uuid:id>/unpublish/', admin_v1.AdminTrackUnpublishView.as_view(), name='v1-admin-content-track-unpublish'),
    path('v1/admin/content/categories/', admin_v1.AdminCategoriesCollectionView.as_view(), name='v1-admin-content-categories'),
    path('v1/admin/content/categories/<uuid:id>/', admin_v1.AdminCategoryDetailView.as_view(), name='v1-admin-content-category-detail'),
    path('v1/admin/content/tracks/bulk-delete/', admin_v1.AdminTracksBulkDeleteView.as_view(), name='v1-admin-content-tracks-bulk-delete'),
    path(
        'v1/admin/content/tracks/bulk-update-visibility/',
        admin_v1.AdminTracksBulkUpdateVisibilityView.as_view(),
        name='v1-admin-content-tracks-bulk-update-visibility',
    ),

    # 3) Playlists
    path('v1/admin/playlists/', admin_v1.AdminPlaylistsCollectionView.as_view(), name='v1-admin-playlists'),
    path('v1/admin/playlists/<uuid:id>/', admin_v1.AdminPlaylistDetailView.as_view(), name='v1-admin-playlist-detail'),
    path('v1/admin/playlists/<uuid:id>/tracks/', admin_v1.AdminPlaylistTracksAddView.as_view(), name='v1-admin-playlist-tracks-add'),
    path(
        'v1/admin/playlists/<uuid:id>/tracks/<uuid:track_id>/',
        admin_v1.AdminPlaylistTrackRemoveView.as_view(),
        name='v1-admin-playlist-track-remove',
    ),
    path('v1/admin/playlists/<uuid:id>/reorder/', admin_v1.AdminPlaylistReorderView.as_view(), name='v1-admin-playlist-reorder'),

    # 4) Users & roles
    path('v1/admin/users/', admin_v1.AdminUsersCollectionView.as_view(), name='v1-admin-users'),
    path('v1/admin/users/<uuid:id>/', admin_v1.AdminUserDetailView.as_view(), name='v1-admin-user-detail'),
    path('v1/admin/users/<uuid:id>/activate/', admin_v1.AdminUserActivateView.as_view(), name='v1-admin-user-activate'),
    path('v1/admin/users/<uuid:id>/deactivate/', admin_v1.AdminUserDeactivateView.as_view(), name='v1-admin-user-deactivate'),
    path('v1/admin/users/<uuid:id>/reset-password/', admin_v1.AdminUserResetPasswordView.as_view(), name='v1-admin-user-reset-password'),
    path('v1/admin/roles/', admin_v1.AdminRolesListView.as_view(), name='v1-admin-roles'),
    path('v1/admin/users/<uuid:id>/role/', admin_v1.AdminUserRoleUpdateView.as_view(), name='v1-admin-user-role'),

    # 5) Paywall & premium
    path('v1/admin/premium/summary/', admin_v1.AdminPremiumSummaryView.as_view(), name='v1-admin-premium-summary'),
    path('v1/admin/premium/settings/', admin_v1.AdminPremiumSettingsView.as_view(), name='v1-admin-premium-settings'),
    path(
        'v1/admin/premium/subscriptions/',
        admin_v1.AdminPremiumSubscriptionsCollectionView.as_view(),
        name='v1-admin-premium-subscriptions',
    ),
    path(
        'v1/admin/premium/subscriptions/<uuid:id>/',
        admin_v1.AdminPremiumSubscriptionDetailView.as_view(),
        name='v1-admin-premium-subscription-detail',
    ),
    path('v1/admin/premium/payments/', admin_v1.AdminPremiumPaymentsCollectionView.as_view(), name='v1-admin-premium-payments'),
    path(
        'v1/admin/premium/payments/<uuid:id>/',
        admin_v1.AdminPremiumPaymentDetailView.as_view(),
        name='v1-admin-premium-payment-detail',
    ),

    # 6) Recommendations
    path(
        'v1/admin/recommendations/rules/',
        admin_v1.AdminRecommendationRulesCollectionView.as_view(),
        name='v1-admin-recommendation-rules',
    ),
    path(
        'v1/admin/recommendations/rules/<uuid:id>/',
        admin_v1.AdminRecommendationRuleDetailView.as_view(),
        name='v1-admin-recommendation-rule-detail',
    ),
    path(
        'v1/admin/recommendations/rules/<uuid:id>/activate/',
        admin_v1.AdminRecommendationRuleActivateView.as_view(),
        name='v1-admin-recommendation-rule-activate',
    ),
    path(
        'v1/admin/recommendations/rules/<uuid:id>/deactivate/',
        admin_v1.AdminRecommendationRuleDeactivateView.as_view(),
        name='v1-admin-recommendation-rule-deactivate',
    ),
    path(
        'v1/admin/recommendations/reorder/',
        admin_v1.AdminRecommendationReorderView.as_view(),
        name='v1-admin-recommendation-reorder',
    ),

    # 7) Platform settings
    path('v1/admin/settings/platform/', admin_v1.AdminPlatformSettingsView.as_view(), name='v1-admin-settings-platform'),

    # 8) Analytics
    path('v1/admin/analytics/overview/', admin_v1.AdminAnalyticsOverviewView.as_view(), name='v1-admin-analytics-overview'),
    path('v1/admin/analytics/users/', admin_v1.AdminAnalyticsUsersView.as_view(), name='v1-admin-analytics-users'),
    path(
        'v1/admin/analytics/conversions/',
        admin_v1.AdminAnalyticsConversionsView.as_view(),
        name='v1-admin-analytics-conversions',
    ),
    path('v1/admin/analytics/revenue/', admin_v1.AdminAnalyticsRevenueView.as_view(), name='v1-admin-analytics-revenue'),

    # 9) Notifications
    path('v1/admin/notifications/', admin_v1.AdminNotificationsCollectionView.as_view(), name='v1-admin-notifications'),
    path('v1/admin/notifications/send/', admin_v1.AdminNotificationsSendView.as_view(), name='v1-admin-notifications-send'),

    # 9.5) Support chat
    path('v1/admin/support/tickets/', admin_v1.AdminSupportTicketsCollectionView.as_view(), name='v1-admin-support-tickets'),
    path('v1/admin/support/tickets/<uuid:id>/', admin_v1.AdminSupportTicketDetailView.as_view(), name='v1-admin-support-ticket-detail'),
    path('v1/admin/support/tickets/<uuid:id>/messages/', admin_v1.AdminSupportTicketMessagesView.as_view(), name='v1-admin-support-ticket-messages'),
    path('v1/admin/support/tickets/<uuid:id>/assign/', admin_v1.AdminSupportTicketAssignView.as_view(), name='v1-admin-support-ticket-assign'),
    path('v1/admin/support/tickets/<uuid:id>/status/', admin_v1.AdminSupportTicketStatusView.as_view(), name='v1-admin-support-ticket-status'),
    path('v1/admin/support/tickets/<uuid:id>/read/', admin_v1.AdminSupportTicketReadView.as_view(), name='v1-admin-support-ticket-read'),
    path('v1/admin/support/summary/', admin_v1.AdminSupportSummaryView.as_view(), name='v1-admin-support-summary'),

    # 10) System health
    path('v1/admin/system/health/', admin_v1.AdminSystemHealthView.as_view(), name='v1-admin-system-health'),
    path('v1/admin/system/storage/', admin_v1.AdminSystemStorageView.as_view(), name='v1-admin-system-storage'),
    path('v1/admin/system/cache/', admin_v1.AdminSystemCacheView.as_view(), name='v1-admin-system-cache'),
]
