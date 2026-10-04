#include maps\mp\_utility;
#include maps\mp\gametypes\_hud_util;
#include common_scripts\utility;

init() {
	level thread player_connect();

	wait 0.5;
}

player_connect() {
	level endon("game_ended");

	for(;;) {
		level waittill("connected", player);
		
		player iprintlnbold("ez patch loaded!");
		
		player setClientDvar("cg_fov", "90");
		
		wait 0.5;
	}
}