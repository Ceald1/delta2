
try:
    from delta2.colors import colors

except ImportError:
    from colors import colors
import random









windows = f"""
{colors.GREEN}                           ....iilll
{colors.GREEN}                 ....iilllllllllllll
{colors.RED}     ....iillll  {colors.GREEN}lllllllllllllllllll
{colors.RED} iillllllllllll  {colors.GREEN}lllllllllllllllllll
{colors.RED} llllllllllllll  {colors.GREEN}lllllllllllllllllll
{colors.RED} llllllllllllll  {colors.GREEN}lllllllllllllllllll
{colors.RED} llllllllllllll  {colors.GREEN}lllllllllllllllllll
{colors.RED} llllllllllllll  {colors.GREEN}lllllllllllllllllll
{colors.RED} llllllllllllll  {colors.GREEN}lllllllllllllllllll
 
{colors.BLUE} llllllllllllll  {colors.YELLOW}lllllllllllllllllll
{colors.BLUE} llllllllllllll  {colors.YELLOW}lllllllllllllllllll
{colors.BLUE} llllllllllllll  {colors.YELLOW}lllllllllllllllllll
{colors.BLUE} llllllllllllll  {colors.YELLOW}lllllllllllllllllll
{colors.BLUE} llllllllllllll  {colors.YELLOW}lllllllllllllllllll
{colors.BLUE} `^^^^^^lllllll  {colors.YELLOW}lllllllllllllllllll
{colors.BLUE}       ````^^^^  {colors.YELLOW}^^lllllllllllllllll
{colors.BLUE}                 {colors.YELLOW}     ````^^^^^^llll {colors.RESET}
"""

# windows = """
#                             .oodMMMM
#                    .oodMMMMMMMMMMMMM
#        ..oodMMM  MMMMMMMMMMMMMMMMMMM
#  oodMMMMMMMMMMM  MMMMMMMMMMMMMMMMMMM
#  MMMMMMMMMMMMMM  MMMMMMMMMMMMMMMMMMM
#  MMMMMMMMMMMMMM  MMMMMMMMMMMMMMMMMMM
#  MMMMMMMMMMMMMM  MMMMMMMMMMMMMMMMMMM
#  MMMMMMMMMMMMMM  MMMMMMMMMMMMMMMMMMM
#  MMMMMMMMMMMMMM  MMMMMMMMMMMMMMMMMMM
 
#  MMMMMMMMMMMMMM  MMMMMMMMMMMMMMMMMMM
#  MMMMMMMMMMMMMM  MMMMMMMMMMMMMMMMMMM
#  MMMMMMMMMMMMMM  MMMMMMMMMMMMMMMMMMM
#  MMMMMMMMMMMMMM  MMMMMMMMMMMMMMMMMMM
#  MMMMMMMMMMMMMM  MMMMMMMMMMMMMMMMMMM
#  `^^^^^^MMMMMMM  MMMMMMMMMMMMMMMMMMM
#        ````^^^^  ^^MMMMMMMMMMMMMMMMM
#                       ````^^^^^^MMMM
# """
ufo = fr"""
{colors.LIGHT_GREY}     ___
{colors.LIGHT_GREY} ___/   \___
{colors.LIGHT_GREY}/   '---'   \
{colors.LIGHT_GREY}'--_______--'
{colors.GREEN}     / \
{colors.GREEN}    /   \
{colors.GREEN}    /\O/\
{colors.GREEN}    / | \
{colors.GREEN}    // \\
{colors.RESET}
"""

# spaceman = fr"""
# {colors.WHITE}        _..._
# {colors.WHITE}      .'     '.      _
# {colors.WHITE}     /    .-""-\   _/ \
# {colors.WHITE}   .-|   /:.   |  |   |
# {colors.WHITE}   |  \  |:.   /.-'-./
# {colors.WHITE}   | .-'-;:__.'    =/
# {colors.WHITE}   .'=  *=|     _.='
# {colors.WHITE}  /   _.  |    ;
# {colors.WHITE} ;-.-'|    \   |
# {colors.WHITE}/   | \    _\  _\
# {colors.WHITE}\__/'._;.  ==' ==\
# {colors.WHITE}         \    \   |
# {colors.WHITE}         /    /   /
# {colors.WHITE}         /-._/-._/
# {colors.WHITE}         \   `\  \
# {colors.WHITE}          `-._/._/

# """


spaceman = fr"""
                 {colors.RED}'
            {colors.BLUE}*          {colors.BRIGHT_RED}.
                   {colors.BRIGHT_BLUE}*       {colors.BRIGHT_GREEN}'
              {colors.MAGENTA}*                {colors.BRIGHT_YELLOW}*
                                                {colors.BRIGHT_MAGENTA}*
{colors.WHITE}        _..._                     {colors.ORANGE}.
{colors.WHITE}      .'     '.      _                {colors.BRIGHT_BLUE}'
{colors.WHITE}     /    .-""-\   _/ \       {colors.BRIGHT_BLUE}*
{colors.WHITE}   .-|   /:.   |  |   |               {colors.BRIGHT_MAGENTA}*
{colors.WHITE}   |  \  |:.   /.-'-./
{colors.WHITE}   | .-'-;:__.'    =/
{colors.WHITE}   .'=  *=|     _.='
{colors.WHITE}  /   _.  |    ;
{colors.WHITE} ;-.-'|    \   |
{colors.WHITE}/   | \    _\  _\
{colors.WHITE}\__/'._;.  ==' ==\
{colors.WHITE}         \    \   |
{colors.WHITE}         /    /   /
{colors.WHITE}         /-._/-._/
{colors.WHITE}         \   `\  \
{colors.WHITE}          `-._/._/
   {colors.ORANGE}*   {colors.BRIGHT_ORANGE}'*
           {colors.BLUE}*
                {colors.BRIGHT_CYAN}*
                       {colors.BRIGHT_GREEN}*
               {colors.BRIGHT_RED}*
                     {colors.BRIGHT_YELLOW}*
{colors.RESET}
"""

blackhole = fr"""
{colors.BRIGHT_ORANGE}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⢠⢀⡐⢄⢢⡐⢢⢁⠂⠄⠠⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
{colors.BRIGHT_ORANGE}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⡄⣌⠰⣘⣆⢧⡜⣮⣱⣎⠷⣌⡞⣌⡒⠤⣈⠠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
{colors.BRIGHT_ORANGE}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠒⠊⠀⠀⠀⠀⢀⠢⠱⡜⣞⣳⠝⣘⣭⣼⣾⣷⣶⣶⣮⣬⣥⣙⠲⢡⢂⠡⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
{colors.BRIGHT_ORANGE}⠀⠀⠀⠀⠀⠀⠀⠃⠀⠀⠀⠀⠀⠀⢀⠢⣑⢣⠝⣪⣵⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣯⣻⢦⣍⠢⢅⢂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
{colors.BRIGHT_ORANGE}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⢆⡱⠌⣡⢞⣵⣿⣿⣿⠿⠛⠛⠉⠉⠛⠛⠿⢷⣽⣻⣦⣎⢳⣌⠆⡱⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
{colors.BRIGHT_ORANGE}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠂⠠⠌⢢⢃⡾⣱⣿⢿⡾⠋{colors.BLACK}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{colors.BRIGHT_ORANGE}⠉⢻⣏⠻⣷⣬⡳⣤⡂⠜⢠⡀⣀⠀⠀⡀⠀⠀⠀⠀⠀⠀
{colors.BRIGHT_ORANGE}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⢀⠂⣌⢃⡾⢡⣿⢣⡏{colors.BLACK}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{colors.BRIGHT_ORANGE}⢹⡇⡊⣿⣿⣾⣽⣛⠶⣶⣬⣭⣥⣙⣚⢷⣶⠦⡤⢀
{colors.BRIGHT_ORANGE}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⢁⠂⠰⡌⡼⠡⣼⢃⡿{colors.BLACK}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{colors.BRIGHT_ORANGE}⢻⣿⣿⣿⣿⣿⣿⣿⣿⣾⡿⠿⣛⣯⡴⢏⠳⠁⠀
{colors.BRIGHT_ORANGE}⠀⠀⠀⠀⠀⠀⠀⠀⠠⠑⡌⠀⣉⣾⣩⣼⣿⣾⡇{colors.BLACK}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{colors.BRIGHT_ORANGE}⢀⣀⣀⣠⣤⣤⣿⣿⣿⣿⡿⢛⣛⣯⣭⠶⣞⠻⣉⠒⠀⠂⠀⠀⠀
{colors.BRIGHT_ORANGE}⠀⠀⠀⠀⠀⠀⢀⣀⡶⢝⣢⣾⣿⣼⣿⣿⣿⣿⣿{colors.BLACK}{colors.BRIGHT_ORANGE}⣀⣼⣀⣀⣀⣤⣴⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⣿⠿⡛⠏⠍⠂⠁⢠⠁⠀⠀⠀⠀⠀⠀⠀
{colors.BRIGHT_ORANGE}⠀⠠⢀⢥⣰⣾⣿⣯⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⣽⠟⣿⠐⠨⠑⡀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
{colors.BRIGHT_ORANGE}⡐⢢⣟⣾⣿⣿⣟⣛⣿⣿⣿⣿⢿⣝⠻⠿⢿⣯⣛⢿⣿⣿⣿⡛⠻⠿⣛⠻⠛⡛⠩⢁⣴⡾⢃⣾⠇⢀⠡⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
{colors.BRIGHT_ORANGE}⠈⠁⠊⠙⠉⠩⠌⠉⠢⠉⠐⠈⠂⠈⠁⠉⠂⠐⠉⣻⣷⣭⠛⠿⣶⣦⣤⣤⣴⣴⡾⠟⣫⣾⣿⡏⠀⠂⠐⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
{colors.BRIGHT_ORANGE}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⢻⢿⢶⣤⣬⣉⣉⣭⣤⣴⣿⣿⡿⠃⠄⡈⠁⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
{colors.BRIGHT_ORANGE}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠘⢊⠳⠭⡽⣿⠿⠿⠟⠛⠉⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
{colors.BRIGHT_ORANGE}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠁⠈⠐⠀⠘⠀⠈⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
{colors.RESET}
"""

xenomorph = fr"""
{colors.DARK_GREEN}         __.,,------.._
{colors.DARK_GREEN}      ,'"   _      _   "`.
{colors.DARK_GREEN}     /.__, ._  -=- _"`    Y
{colors.DARK_GREEN}    (.____.-.`      ""`   j
{colors.DARK_GREEN}     VvvvvvV`.Y,.    _.,-'       ,     ,     ,
{colors.DARK_GREEN}        Y    ||,   '"\         ,/    ,/    ./
{colors.DARK_GREEN}        |   ,'  ,     `-..,'_,'/___,'/   ,'/   ,
{colors.DARK_GREEN}   ..  ,;,,',-'"\,'  ,  .     '     ' ""' '--,/    .. ..
{colors.DARK_GREEN} ,'. `.`---'     `, /  , Y -=-    ,'   ,   ,. .`-..||_|| ..
{colors.DARK_GREEN}ff\\`. `._        /f ,'j j , ,' ,   , f ,  \=\ Y   || ||`||_..
{colors.DARK_GREEN}l` \` `.`."`-..,-' j  /./ /, , / , / /l \   \=\l   || `' || ||...
{colors.DARK_GREEN} `  `   `-._ `-.,-/ ,' /`"/-/-/-/-"'''"`.`.  `'.\--`'--..`'_`' || ,
{colors.DARK_GREEN}            "`-_,',  ,'  f    ,   /      `._    ``._     ,  `-.`'//         ,
{colors.DARK_GREEN}          ,-"'' _.,-'    l_,-'_,,'          "`-._ . "`. /|     `.'\ ,       |
{colors.DARK_GREEN}        ,',.,-'"          \=) ,`-.         ,    `-'._`.V |       \ // .. . /j
{colors.DARK_GREEN}        |f\\               `._ )-."`.     /|         `.| |        `.`-||-\\/
{colors.DARK_GREEN}        l` \`                 "`._   "`--' j          j' j          `-`---'
{colors.DARK_GREEN}         `  `                     "`,-  ,'/       ,-'"  /
{colors.DARK_GREEN}                                 ,'",__,-'       /,, ,-'
{colors.DARK_GREEN}                                 Vvv'            VVv'
{colors.RESET}
"""






def random_art():
    arts = [windows, ufo, spaceman, blackhole, xenomorph]
    art = random.choice(arts)
    return art