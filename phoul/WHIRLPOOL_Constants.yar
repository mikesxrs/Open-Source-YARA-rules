rule WHIRLPOOL_Constants {
        meta:
                author = "phoul (@phoul)"
                description = "Look for WhirlPool constants"
                date = "2014-02"
                version = "0.1"
        strings:
                $c0 = { 18186018c07830d8 }
                $c1 = { d83078c018601818 }
                $c2 = { 23238c2305af4626 }
                $c3 = { 2646af05238c2323 }
        condition:
                2 of them
}


