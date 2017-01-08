/* Check the entropy of the files being checked */

import "math"

rule math_entropy_close_8 : statistics {
	condition:
		math.entropy(0, filesize) >= 7.5
}

rule math_entropy_7 : statistics {
	condition:
		math.entropy(0, filesize) >= 7 and
		math.entropy(0, filesize) < 7.5
}

rule math_entropy_6 : statistics {
	condition:
		math.entropy(0, filesize) >= 6 and
		math.entropy(0, filesize) < 7
}

rule math_entropy_5 : statistics {
	condition:
		math.entropy(0, filesize) >= 5 and
		math.entropy(0, filesize) < 6
}

rule math_entropy_4 : statistics {
	condition:
		math.entropy(0, filesize) >= 4 and
		math.entropy(0, filesize) < 5
}

rule math_entropy_3 : statistics {
	condition:
		math.entropy(0, filesize) >= 3 and
		math.entropy(0, filesize) < 4
}

rule math_entropy_2 : statistics {
	condition:
		math.entropy(0, filesize) >= 2 and
		math.entropy(0, filesize) < 3
}

rule math_entropy_1 : statistics {
	condition:
		math.entropy(0, filesize) >= 1 and
		math.entropy(0, filesize) < 2
}

rule math_entropy_0 : statistics {
	condition:
		math.entropy(0, filesize) >= 0 and
		math.entropy(0, filesize) < 1
}

