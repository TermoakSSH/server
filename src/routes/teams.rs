//! Teams: create them, manage members and see which teams you can share with.
//!
//! Permissions:
//! - Any user can create a team (and becomes its owner).
//! - Team owners and admins manage the members.
//! - Only an owner appoints other owners or deletes the team.
//! - Anyone can leave a team (except the last owner).
//! - A server administrator can do all of the above.
//! - Team owners and admins can invite by email people without an account
//!   (if registration is open; otherwise only a server administrator).

use axum::extract::{Path, State};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use termoak_core::Id;
use termoak_core::model::{Invite, Team, TeamMember, TeamRole};
use termoak_core::store::invites::NewInvite;
use utoipa::ToSchema;

use crate::auth::{AdminUser, AuthUser};
use crate::config::Registration;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/teams", get(list).post(create))
        .route("/api/v1/teams/{id}", get(one).patch(rename).delete(remove))
        .route("/api/v1/teams/{id}/members", get(members).post(add_member))
        .route(
            "/api/v1/teams/{id}/members/{user_id}",
            patch(set_role).delete(remove_member),
        )
        .route(
            "/api/v1/teams/{id}/invites",
            get(team_invites).post(invite_by_email),
        )
        .route(
            "/api/v1/teams/{id}/invites/{invite_id}",
            delete(revoke_team_invite),
        )
        .route("/api/v1/admin/teams/{id}/plan", post(set_plan))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct TeamInviteRequest {
    pub email: String,
    #[serde(default = "default_role")]
    pub role: TeamRole,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetPlan {
    pub plan: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateTeam {
    pub name: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AddMember {
    /// Email of a user of this server.
    pub email: String,
    #[serde(default = "default_role")]
    pub role: TeamRole,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetRole {
    pub role: TeamRole,
}

fn default_role() -> TeamRole {
    TeamRole::Member
}

/// Effective role of the caller: their own or, for a server administrator,
/// owner.
async fn acting_role(st: &AppState, u: &AuthUser, team: Id) -> ApiResult<Option<TeamRole>> {
    let role = st.store.team_role(team, u.id()).await?;
    Ok(if u.user.is_admin {
        Some(TeamRole::Owner)
    } else {
        role
    })
}

async fn require_role(st: &AppState, u: &AuthUser, team: Id, min: TeamRole) -> ApiResult<TeamRole> {
    // If the team does not exist, answer 404 rather than 403.
    st.store.team_for(team, u.id()).await?;
    match acting_role(st, u, team).await? {
        Some(r) if r >= min => Ok(r),
        Some(_) => Err(match min {
            TeamRole::Owner => {
                ApiError::forbidden("only a team owner can do this").with_code("team_owner_only")
            }
            _ => ApiError::forbidden("only team owners and admins can do this")
                .with_code("team_admin_only"),
        }),
        None => Err(ApiError::not_found("team not found")),
    }
}

/// Your teams; a server administrator sees all of them (with their role in
/// the ones they belong to).
async fn list(State(st): State<AppState>, u: AuthUser) -> ApiResult<Json<Vec<Team>>> {
    if u.user.is_admin {
        return Ok(Json(st.store.all_teams(u.id()).await?));
    }
    Ok(Json(st.store.teams_of(u.id()).await?))
}

async fn create(
    State(st): State<AppState>,
    u: AuthUser,
    Json(req): Json<CreateTeam>,
) -> ApiResult<Json<Team>> {
    crate::account::check_new_team(&st, &u.user).await?;
    let team = st.store.create_team(u.id(), &req.name).await?;
    st.store
        .audit(
            u.id(),
            &u.actor(),
            "team.created",
            Some(team.id.to_string()),
            json!({"name": team.name}),
        )
        .await?;
    Ok(Json(team))
}

async fn one(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
) -> ApiResult<Json<Value>> {
    require_role(&st, &u, id, TeamRole::Member).await?;
    let team = st.store.team_for(id, u.id()).await?;
    let members = st.store.team_members(id).await?;
    Ok(Json(json!({"team": team, "members": members})))
}

async fn members(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
) -> ApiResult<Json<Vec<TeamMember>>> {
    require_role(&st, &u, id, TeamRole::Member).await?;
    Ok(Json(st.store.team_members(id).await?))
}

async fn rename(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
    Json(req): Json<CreateTeam>,
) -> ApiResult<Json<Team>> {
    require_role(&st, &u, id, TeamRole::Admin).await?;
    st.store.rename_team(id, &req.name).await?;
    Ok(Json(st.store.team_for(id, u.id()).await?))
}

async fn remove(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
) -> ApiResult<Json<Value>> {
    require_role(&st, &u, id, TeamRole::Owner).await?;
    let shares = st.store.team_shares(id).await?;
    // Its vaults go with it (and the grants it had on other vaults).
    let team_vaults: Vec<Id> = st
        .store
        .team_vaults(id)
        .await?
        .into_iter()
        .map(|v| v.id)
        .collect();
    let before = crate::vaults::snapshot(&st, st.store.team_member_ids(id).await?).await;
    st.store.delete_team(id).await?;
    for v in &team_vaults {
        st.sessions.close_for_vault(None, *v).await;
        st.pool.invalidate_vault(*v, None).await;
    }
    crate::vaults::apply_revocations(&st, before, &team_vaults).await;
    // Out of the sessions shared with the team, unless they have another
    // valid share.
    for share in shares {
        if let Some(live) = st.sessions.get(share.session_id) {
            let using = live.room().with_share(share.id);
            st.sessions
                .reevaluate(&live, crate::room::EndCode::Revoked, Some(&using))
                .await;
        }
    }
    st.store
        .audit(
            u.id(),
            &u.actor(),
            "team.deleted",
            Some(id.to_string()),
            json!({}),
        )
        .await?;
    Ok(Json(json!({"ok": true})))
}

async fn add_member(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
    Json(req): Json<AddMember>,
) -> ApiResult<Json<Vec<TeamMember>>> {
    let mine = require_role(&st, &u, id, TeamRole::Admin).await?;
    if req.role == TeamRole::Owner && mine != TeamRole::Owner {
        return Err(
            ApiError::forbidden("only an owner can appoint owners").with_code("team_owner_only")
        );
    }
    let user = st.store.user_by_email(&req.email).await?.ok_or_else(|| {
        ApiError::not_found("there is no user with that email on this server")
            .with_code("user_not_found")
    })?;
    if user.disabled {
        return Err(ApiError::bad_request("that account is disabled").with_code("account_disabled"));
    }
    add_existing(&st, &u, id, &user, req.role).await?;
    Ok(Json(st.store.team_members(id).await?))
}

/// Adds a user who already has an account and lets them know by email.
async fn add_existing(
    st: &AppState,
    u: &AuthUser,
    team_id: Id,
    user: &termoak_core::model::User,
    role: TeamRole,
) -> ApiResult<()> {
    if st.store.team_role(team_id, user.id).await?.is_some() {
        return Err(ApiError::conflict("already a team member").with_code("already_member"));
    }
    let team = st.store.team_for(team_id, u.id()).await?;
    crate::account::check_team_size(st, &team.plan, team.member_count)?;
    let before = crate::vaults::snapshot(st, [user.id]).await;
    st.store.set_team_member(team_id, user.id, role).await?;
    crate::vaults::apply_revocations(st, before, &[]).await;
    st.store
        .audit(
            u.id(),
            &u.actor(),
            "team.member_added",
            Some(team_id.to_string()),
            json!({"user": user.id, "role": role.as_str()}),
        )
        .await?;
    if let Some(push) = &st.push
        && user.id != u.id()
    {
        push.team_added(user.id, team_id, &team.name, &display_name(u));
    }
    if st.mailer.enabled() && user.id != u.id() {
        let link = format!("{}/app/teams", st.config.base_url());
        st.mailer.send_later(crate::email::added_to_team(
            &user.email,
            &user.locale,
            &display_name(u),
            &team.name,
            &link,
        ));
    }
    Ok(())
}

fn display_name(u: &AuthUser) -> String {
    if u.user.name.trim().is_empty() {
        u.user.email.clone()
    } else {
        u.user.name.clone()
    }
}

/// Pending team invitations.
async fn team_invites(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
) -> ApiResult<Json<Vec<Invite>>> {
    require_role(&st, &u, id, TeamRole::Admin).await?;
    Ok(Json(st.store.team_invites(id).await?))
}

/// Invites by email: a person with an account joins directly; otherwise
/// they get an invitation to sign up that adds them to the team.
async fn invite_by_email(
    State(st): State<AppState>,
    u: AuthUser,
    Path(id): Path<Id>,
    Json(req): Json<TeamInviteRequest>,
) -> ApiResult<Json<Value>> {
    let mine = require_role(&st, &u, id, TeamRole::Admin).await?;
    if req.role == TeamRole::Owner && mine != TeamRole::Owner {
        return Err(
            ApiError::forbidden("only an owner can appoint owners").with_code("team_owner_only")
        );
    }
    let email = req.email.trim().to_lowercase();
    if let Some(user) = st.store.user_by_email(&email).await? {
        if user.disabled {
            return Err(
                ApiError::bad_request("that account is disabled").with_code("account_disabled")
            );
        }
        add_existing(&st, &u, id, &user, req.role).await?;
        return Ok(Json(json!({
            "added": true,
            "members": st.store.team_members(id).await?,
        })));
    }
    if st.config.server.registration != Registration::Open && !u.user.is_admin {
        return Err(ApiError::forbidden(
            "that person has no account and registration is closed: ask a server administrator to invite them",
        )
        .with_code("registration_closed"));
    }
    let team = st.store.team_for(id, u.id()).await?;
    crate::account::check_team_size(&st, &team.plan, team.member_count)?;
    let (invite, token) = st
        .store
        .create_invite(
            u.id(),
            NewInvite {
                email: Some(email),
                is_admin: false,
                team_id: Some(id),
                team_role: Some(req.role),
                expires_at: Some(termoak_core::time::now_ms() + 7 * 24 * 3_600_000),
            },
        )
        .await?;
    st.store
        .audit(
            u.id(),
            &u.actor(),
            "team.invite_created",
            Some(id.to_string()),
            json!({"invite": invite.id, "email": invite.email, "role": req.role.as_str()}),
        )
        .await?;
    let (server, url, web_url) = crate::auth::invite_links(&st, &token);
    let emailed =
        crate::auth::send_invite_email(&st, &u, &invite, web_url.as_deref().unwrap_or(&url), true)
            .await;
    Ok(Json(json!({
        "added": false,
        "invite": invite,
        "token": token,
        "server": server,
        "url": url,
        "web_url": web_url,
        "emailed": emailed,
    })))
}

async fn revoke_team_invite(
    State(st): State<AppState>,
    u: AuthUser,
    Path((id, invite_id)): Path<(Id, Id)>,
) -> ApiResult<Json<Value>> {
    require_role(&st, &u, id, TeamRole::Admin).await?;
    let invite = st.store.invite(invite_id).await?;
    if invite.team_id != Some(id) {
        return Err(ApiError::not_found("invitation not found"));
    }
    st.store.revoke_invite(invite_id).await?;
    st.store
        .audit(
            u.id(),
            &u.actor(),
            "team.invite_revoked",
            Some(id.to_string()),
            json!({"invite": invite_id}),
        )
        .await?;
    Ok(Json(json!({"ok": true})))
}

/// Changes a team's plan (server administrators).
async fn set_plan(
    State(st): State<AppState>,
    AdminUser(a): AdminUser,
    Path(id): Path<Id>,
    Json(req): Json<SetPlan>,
) -> ApiResult<Json<Team>> {
    if !st.config.plans.exists(&req.plan) {
        return Err(
            ApiError::bad_request(format!("plan \"{}\" does not exist", req.plan))
                .with_code("unknown_plan"),
        );
    }
    st.store.set_team_plan(id, &req.plan).await?;
    st.store
        .audit(
            a.id(),
            &a.actor(),
            "admin.team_plan",
            Some(id.to_string()),
            json!({"plan": req.plan}),
        )
        .await?;
    Ok(Json(st.store.team_for(id, a.id()).await?))
}

async fn set_role(
    State(st): State<AppState>,
    u: AuthUser,
    Path((id, user_id)): Path<(Id, Id)>,
    Json(req): Json<SetRole>,
) -> ApiResult<Json<Vec<TeamMember>>> {
    let mine = require_role(&st, &u, id, TeamRole::Admin).await?;
    let current = st
        .store
        .team_role(id, user_id)
        .await?
        .ok_or_else(|| ApiError::not_found("not a team member"))?;
    // Changing an owner or appointing one is up to owners.
    if (current == TeamRole::Owner || req.role == TeamRole::Owner) && mine != TeamRole::Owner {
        return Err(ApiError::forbidden("only an owner can change other owners")
            .with_code("team_owner_only"));
    }
    if current == TeamRole::Owner
        && req.role != TeamRole::Owner
        && st.store.team_owner_count(id).await? <= 1
    {
        return Err(ApiError::conflict(
            "the team would be left without an owner: appoint another one first",
        )
        .with_code("last_team_owner"));
    }
    let before = crate::vaults::snapshot(&st, [user_id]).await;
    st.store.set_team_member(id, user_id, req.role).await?;
    crate::vaults::apply_revocations(&st, before, &[]).await;
    st.store
        .audit(
            u.id(),
            &u.actor(),
            "team.role_changed",
            Some(id.to_string()),
            json!({"user": user_id, "role": req.role.as_str()}),
        )
        .await?;
    Ok(Json(st.store.team_members(id).await?))
}

async fn remove_member(
    State(st): State<AppState>,
    u: AuthUser,
    Path((id, user_id)): Path<(Id, Id)>,
) -> ApiResult<Json<Value>> {
    let leaving = user_id == u.id();
    if !leaving {
        let mine = require_role(&st, &u, id, TeamRole::Admin).await?;
        if st.store.team_role(id, user_id).await? == Some(TeamRole::Owner)
            && mine != TeamRole::Owner
        {
            return Err(
                ApiError::forbidden("only an owner can remove another owner")
                    .with_code("team_owner_only"),
            );
        }
    }
    let before = crate::vaults::snapshot(&st, [user_id]).await;
    st.store.remove_team_member(id, user_id).await?;
    // They lose access to the sessions shared with the team, unless they
    // have another invitation (direct or from another team), and to the
    // team's vaults (server sessions on their hosts close).
    st.sessions.reevaluate_user(user_id).await;
    crate::vaults::apply_revocations(&st, before, &[]).await;
    st.store
        .audit(
            u.id(),
            &u.actor(),
            if leaving {
                "team.left"
            } else {
                "team.member_removed"
            },
            Some(id.to_string()),
            json!({"user": user_id}),
        )
        .await?;
    Ok(Json(json!({"ok": true})))
}
