{ pkgs, legacyPolygott }: {
	deps = [
		pkgs.clang_12
		pkgs.ccls
		pkgs.gdb
		pkgs.gnumake
	] ++ legacyPolygott;
}