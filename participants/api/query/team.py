import graphene
from graphql_jwt.decorators import login_required

from participants.models import Team
from participants.api.objects import TeamObj

from framework.api.helper import APIException


class Query(graphene.ObjectType):
    getTeam = graphene.Field(TeamObj, hash=graphene.String(required=True))
    myTeams = graphene.List(TeamObj)

    @login_required
    def resolve_getTeam(self, info, **kwargs):
        user = info.context.user
        try:
            team = Team.objects.get(hash=kwargs.get('hash'))
            if user in team.members.all():
                mlist = []
                for member in team.members.order_by('first_name').all():
                    mlist.append({
                        "name": member.first_name + ' ' + member.last_name,
                        "username": member.username
                    })
                return TeamObj(
                    name=team.name,
                    leader={
                        "name": team.leader.first_name + ' ' + team.leader.last_name,
                        "username": team.leader.username
                    },
                    members=mlist,
                    membersCount=len(mlist),
                    hash=team.hash,
                    isUserLeader=user == team.leader
                )
            else:
                raise APIException("You should be a member of the team to retrieve details of the team.")
        except Team.DoesNotExist:
            raise APIException("The team queried does not exist or have been deleted.")

    @login_required
    def resolve_myTeams(self, info, **kwargs):
        user = info.context.user
        teams = Team.objects.filter(members=user)
        tlist = []
        for team in teams:
            mlist = []
            for member in team.members.order_by('first_name').all():
                mlist.append({
                    "name": member.first_name + ' ' + member.last_name,
                    "username": member.username
                })
            tlist.append({
                "name": team.name,
                "leader": {
                    "name": team.leader.first_name + ' ' + team.leader.last_name,
                    "username": team.leader.username
                },
                "members": mlist,
                "membersCount": len(mlist),
                "hash": team.hash,
                "isUserLeader": user == team.leader
            })
        return tlist
