// Proxy + normaliser for the official Fantasy Premier League API.
// The browser can't call fantasy.premierleague.com directly (CORS), so this
// serverless function fetches on the server and returns a slimmed, stable shape.
//
//   GET /api/fpl?resource=bootstrap
//       -> { teams:{id:{id,name,short}}, players:{id:{id,name,teamId,teamShort,pos}},
//            events:[{id,name,deadline,finished,isCurrent,isNext}], currentGW, nextGW }
//   GET /api/fpl?resource=fixtures&gw=<n>
//       -> { fixtures:[{id,gw,teamHId,teamAId,teamH,teamA,hScore,aScore,finished,kickoff}] }
//   GET /api/fpl?resource=live&gw=<n>
//       -> { points:{ [playerId]: gwPoints } }
//
// Cached briefly at the edge to stay well under any rate limits.
const FPL = 'https://fantasy.premierleague.com/api';
const POS = { 1: 'GK', 2: 'DEF', 3: 'MID', 4: 'FWD' };

async function fplFetch(path) {
  const r = await fetch(`${FPL}${path}`, {
    headers: { 'User-Agent': 'Mozilla/5.0 ProPunditLeague/1.0' },
  });
  if (!r.ok) throw new Error(`FPL ${path} -> ${r.status}`);
  return r.json();
}

export default async function handler(req, res) {
  const resource = req.query.resource || 'bootstrap';
  try {
    if (resource === 'bootstrap') {
      const data = await fplFetch('/bootstrap-static/');
      const teams = {};
      (data.teams || []).forEach(t => { teams[t.id] = { id: t.id, name: t.name, short: t.short_name }; });
      const players = {};
      (data.elements || []).forEach(e => {
        players[e.id] = {
          id: e.id,
          name: e.web_name,
          full: `${e.first_name} ${e.second_name}`.trim(),
          teamId: e.team,
          teamShort: teams[e.team] ? teams[e.team].short : '',
          pos: POS[e.element_type] || '',
          status: e.status, // 'a' available, 'i' injured, 's' suspended, 'u' unavailable
        };
      });
      const events = (data.events || []).map(ev => ({
        id: ev.id, name: ev.name, deadline: ev.deadline_time,
        finished: ev.finished, isCurrent: ev.is_current, isNext: ev.is_next,
      }));
      const cur = events.find(e => e.isCurrent);
      const nxt = events.find(e => e.isNext);
      res.setHeader('Cache-Control', 's-maxage=300, stale-while-revalidate=600');
      return res.status(200).json({
        teams, players, events,
        currentGW: cur ? cur.id : null,
        nextGW: nxt ? nxt.id : (cur ? cur.id : 1),
      });
    }

    if (resource === 'fixtures') {
      const gw = parseInt(req.query.gw, 10);
      if (!gw) return res.status(400).json({ error: 'gw required' });
      const [fixtures, boot] = await Promise.all([
        fplFetch(`/fixtures/?event=${gw}`),
        fplFetch('/bootstrap-static/'),
      ]);
      const short = {};
      (boot.teams || []).forEach(t => { short[t.id] = t.short_name; });
      const out = (fixtures || []).map(f => ({
        id: f.id, gw: f.event,
        teamHId: f.team_h, teamAId: f.team_a,
        teamH: short[f.team_h] || String(f.team_h),
        teamA: short[f.team_a] || String(f.team_a),
        hScore: f.team_h_score, aScore: f.team_a_score,
        finished: !!(f.finished || f.finished_provisional),
        kickoff: f.kickoff_time,
      }));
      res.setHeader('Cache-Control', 's-maxage=60, stale-while-revalidate=120');
      return res.status(200).json({ fixtures: out });
    }

    if (resource === 'live') {
      const gw = parseInt(req.query.gw, 10);
      if (!gw) return res.status(400).json({ error: 'gw required' });
      const data = await fplFetch(`/event/${gw}/live/`);
      const points = {};
      (data.elements || []).forEach(e => {
        points[e.id] = (e.stats && typeof e.stats.total_points === 'number') ? e.stats.total_points : 0;
      });
      res.setHeader('Cache-Control', 's-maxage=60, stale-while-revalidate=120');
      return res.status(200).json({ points });
    }

    return res.status(400).json({ error: 'unknown resource' });
  } catch (err) {
    console.error('fpl error', err);
    return res.status(502).json({ error: String(err && err.message || err) });
  }
}
