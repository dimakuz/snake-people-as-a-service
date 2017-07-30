# WTFPL
import re

_TRANSLATOR = {
    r'\b(M|m)illienial(s)?\b': r'\1illennial\2',
    r'b(M|m)illenial(s)?\b': r'\1illennial\2',
    r'\b(M|m)ilennial(s)?\b': r'\1illennial\2',
    r'\b(M|m)ilenial(s)?\b': r'\1illennial\2',
    r'\b(?:Millennial Generation)|(?:Generation Millennial)\b':
        'Plissken Faction',
    r'\b(?:millennial generation)|(?:generation millennial)\b':
        'Plissken faction',
    r'\bMillennialism\b': 'Reptilianism',
    r'\bmillennialism\b': 'reptilianism',
    r'\bMillennial (M|m)(e|a)n(\'s)?\b': r'Snake \1\2n\3',
    r'\bmillennial m(e|a)n(\'s)?\b': r'snake m\1n\2',
    r'\bMillennial (B|b)oy(\'s|s(?:\')?)?\b': r'Snake \1oy\2',
    r'\bmillennial boy(\'s|s(?:)?)?\b': r'snake boy\1',
    r'\bMillennial (G|g)uy(\'s|s(?:\')?)?\b': r'Snake \1uy\2',
    r'\bmillennial guy(\'s|s(?:\')?)?\b': r'snake guy\1',
    r'\bMillennial (W|w)om(e|a)n(\'s)?\b': r'Snake \1om\2n\3',
    r'\bmillennial wom(e|a)n(\'s)?\b': r'snake wom\1n\2',
    r'\bMillennial (G|g)irl(\'s|s(?:\')?)?\b': r'Snake \1irl\2',
    r'\bmillennial girl(\'s|s(?:\')?)?\b': r'snake girl\1',
    r'\bMillennial (G|g)al(\'s|s(?:\')?)?\b': r'Snake \1al\2',
    r'\bmillennial gal(\'s|s(?:\')?)?\b': r'snake gal\1',
    r'\bMillennial Child(\'s)?\b': r'Snakelet\1',
    r'\b[Mm]illennial child(\'s)?\b': r'snakelet\1',
    r'\bMillennial Children(?:(\')s)?\b': r'Snakelets\1',
    r'\b[Mm]illennial children(?:(\')s)?\b': r'snakelets\1',
    r'\bMillennial [Tt]een(?:ager)?(\'s)?\b': "proto-Snake Person\1",
    r'\bmillennial teen(?:ager)?(\'s)?\b': "proto-snake person\1",
    r'\bMillennial [Tt]een(?:ager)?(?:(s)\b(\')|s\b)':
        "proto-Snake People\2\1",
    r'\bmillennial teen(?:ager)?(?:(s)\b(\')|s\b)': "proto-snake people\2\1",
    r'\bMillennial (A|a)dult(\'s)?\b': "\1dult Snake Person\2",
    r'\bmillennial adult(\'s)?\b': "adult snake person\1",
    r'\bMillennial (A|a)dult(?:(s)\b(\')|s\b)': "\1dult Snake People\3\2",
    r'\bmillennial adult(?:(s)\b(\')|s\b)': "adult snake people\2\1",
    r'\bmil·len·nial\b': "snake peo·ple",
    r'\bmiˈlenēəl\b': "snāk ˈpēpəl",
    r'\bMillennial\b': "Snake Person",
    r'\bmillennial\b': "snake person",
    r'\bMillennial(?:(s)\b(\')|s\b)': "Snake People\2\1",
    r'\bmillennial(?:(s)\b(\')|s\b)': "snake people\2\1",
    r'\bGreat Recession\b': "Time of Shedding and Cold Rocks",
    r'\bgreat recession\b': "time of shedding and cold rocks",
    r'\bGreat Depression\b': "Clutch Plague",
    r'\bgreat depression\b': "clutch plague",
    r'\b(?:(?:Occupy|OWS) (?:M|m)ovement)|(?:Occupy Wall Street)\b':
        "Great Ape-Snake War",
    r'\b(?:(?:occupy|OWS|ows) movement)|(?:occupy wall street)\b':
        "great ape-snake war",
    r'\bOWS\b': "GA-SW",
    r'\bows\b': "ga-sw",
    r'\bHelicopter Parent(?:(s)\b(\')|s\b)': "Thulsa Doom\2\1",
    r'\b[Hh]elicopter parent(?:(s)\b(\')|s\b)': "Thoth-Amon\2\1",
    r'\bTrophy Kid(?:(s)\b(\')|s\b)': "Quetzalcoatl's Chosen\2\1",
    r'\btrophy kid(?:(s)\b(\')|s\b)': "Quetzalcoatl's chosen\2\1",
    r'\bDigital Native(s)?\b': "Parseltongue\1",
    r'\bdigital native(s)?\b': "parseltongue\1",
    r'\bGeneration Z\b': "The Zolom's Children",
    r'\bgeneration Z\b': "the Zolom's children",
    r'\bZ Generation\b': "Children of the Zolom",
    r'\bz generation\b': "children of the Zolom",
    r'\b(?:Generation Y)|(?:Generation Why)\b': "Serpent Society",
    r'\bgen(?:eration)? ?(?:wh)?y\b': "serpent society",
    r'\bGen Y\b': "Society of the Serpent",
    r'\bGeneration We\b': "Caduceus Cult",
    r'\bgeneration we\b': "caduceus cult",
    r'\bWe Generation\b': "Cult of the Caduceus",
    r'\bwe generation\b': "cult of the caduceus",
    r'\bGeneration Me\b': "The Cult of the Serpent",
    r'\bgeneration me\b': "the cult of the serpent",
    r'\bGlobal Generation\b': "Tannin's Horde",
    r'\bglobal generation\b': "Tannin's horde",
    r'\bGeneration Global\b': "Horde of Tannin",
    r'\bgeneration global\b': "horde of Tannin",
    r'\bGeneration Next\b': "Time of Nidhogg",
    r'\bgeneration next\b': "time of Nidhogg",
    r'\bNet Generation\b': "Damballa's Coils",
    r'\bnet generation\b': "Damballa's coils",
    r'\bGeneration Net\b': "Coils of Damballa",
    r'\bgeneration net\b': "Coils of Damballa",
    r'\bEcho Boomers\b': "Crotalids",
    r'\becho Boomers\b': "crotalids",
    r'\bNew Boomer(?:(s)\b(\')|s\b)': "Jörmungandr's Circle\2\1",
    r'\bnew Boomer(?:(s)\b(\')|s\b)': "Jörmungandr's circle\2\1",
    r'\b(?:Generation Flux)|(?:Flux Generation)\b': "Hiss Club",
    r'\b(?:generation flux)|(?:flux generation)\b': "hiss club",
    r'\bGeneration Sell\b': "Kaa Tribe",
    r'\bgeneration sell\b': "Kaa tribe",
    r'\bSell Generation\b': "Tribe of Kaa",
    r'\bsell generation\b': "tribe of Kaa",
    r'\b(?:Boomerang Generation)|(?:Generation Boomerang)\b':
        "Ouroboros Society",
    r'\b(?:boomerang generation)|(?:generation boomerang)\b':
        "ouroboros society",
    r'\bPeter Pan Generation\b': "Neheb-Kau Cult",
    r'\b(?:P|p)eter (?:P|p)an generation\b': "Neheb-Kau cult",
    r'\bGeneration Peter Pan\b': "Cult of Neheb-Kau",
    r'\bgeneration (?:P|p)eter (?:P|p)an\b': "cult of Neheb-Kau",
    r'\bGen(?:eration)? 9\/?11\b': "Kaa Tribe",
    r'\bgen(?:eration)? 9\/?11\b': "Kaa tribe",
    r'\b9\/?11 Generation\b': "Tribe of the Kaa",
    r'\b9\/?11 generation\b': "tribe of the Kaa",
    r'\b(S|s)truggling (A|a)spirationals\b': "Struggling (with) Pythons",
    r'\b(S|s)uccessful (H|h)omeowners\b': "Viper Stripers",
    r'\b(A|a)ctive (A|a)ffluents\b': "Activated Boas",
    r'\b(C|c)omfortable (?:tv|Tv|TV) (W|w)atchers\b': "Cozy Cobras",
    r'\b(?:The Generation of €700)|(?:€700 Generation)\b': "Ophion",
    r'\b(?:the generation of €700)|(?:€700 generation)\b': "ophion",
    r'\b(?:M|m)ill?eurista\b': "Nagual",
    r'\b(?:Precarious Generation)|(?:Generation Precarious)\b': "Gargouille"
}


def translate(input):
    for pat, sub in _TRANSLATOR.items():
        input = re.sub(pat, sub, input, flags=re.DOTALL | re.MULTILINE)
    return input
