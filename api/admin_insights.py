from datetime import timedelta

from django.db.models import Count
from django.db.models.functions import TruncDay, TruncMonth, TruncWeek
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Subscription, User


def _rate(part, whole):
    if whole == 0:
        return 0.0
    return round((part / whole) * 100, 1)


class SummaryView(APIView):
    def get(self, request):
        now = timezone.now()
        thirty_days_ago = now - timedelta(days=30)

        total_users = User.objects.count()
        active_users_30d = User.objects.filter(last_login_at__gte=thirty_days_ago).count()
        premium_users = (
            Subscription.objects.filter(status=Subscription.Status.ACTIVE)
            .values('user_id')
            .distinct()
            .count()
        )
        conversion_rate = _rate(premium_users, total_users)

        return Response(
            {
                'total_users': total_users,
                'active_users_30d': active_users_30d,
                'premium_users': premium_users,
                'conversion_rate': conversion_rate,
            }
        )


class PremiumConversionsView(APIView):
    def get(self, request):
        interval = request.query_params.get('interval', 'weekly')
        trunc_map = {
            'daily': TruncDay('started_at'),
            'weekly': TruncWeek('started_at'),
            'monthly': TruncMonth('started_at'),
        }
        trunc_func = trunc_map.get(interval)
        if trunc_func is None:
            return Response(
                {'error': "invalid interval; use one of: daily, weekly, monthly"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        rows = (
            Subscription.objects.filter(status=Subscription.Status.ACTIVE)
            .annotate(period_dt=trunc_func)
            .values('period_dt')
            .annotate(count=Count('user_id', distinct=True))
            .order_by('period_dt')
        )

        data = []
        for row in rows:
            period_dt = row['period_dt']
            if interval == 'daily':
                period = period_dt.strftime('%Y-%m-%d')
            elif interval == 'weekly':
                iso_year, iso_week, _ = period_dt.isocalendar()
                period = f'{iso_year}-W{iso_week:02d}'
            else:
                period = period_dt.strftime('%Y-%m')
            data.append({'period': period, 'count': row['count']})

        return Response({'interval': interval, 'data': data})


class ConversionFunnelView(APIView):
    def get(self, request):
        total_users = User.objects.count()
        trial_users = (
            Subscription.objects.filter(status=Subscription.Status.TRIAL)
            .values('user_id')
            .distinct()
            .count()
        )
        premium_users = (
            Subscription.objects.filter(status=Subscription.Status.ACTIVE)
            .values('user_id')
            .distinct()
            .count()
        )
        non_free_users = (
            User.objects.filter(subscription__status__in=[Subscription.Status.TRIAL, Subscription.Status.ACTIVE])
            .distinct()
            .count()
        )
        free_users = total_users - non_free_users
        if free_users < 0:
            free_users = 0

        free_to_trial_rate = _rate(trial_users, free_users)
        trial_to_premium_rate = _rate(premium_users, trial_users)

        return Response(
            {
                'free_users': free_users,
                'trial_users': trial_users,
                'premium_users': premium_users,
                'free_to_trial_rate': free_to_trial_rate,
                'trial_to_premium_rate': trial_to_premium_rate,
            }
        )
