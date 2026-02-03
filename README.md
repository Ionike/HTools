## HTools
Scripts for my Doujin manga and game collection.

# Introduction

/DLsite:

./game_renamer_v2.py: Select a parent folder path, rename games in each folder in parent folder. It uses Local LLM to extract game folder contents, including folder name, exe title, .txt contents then decide the search term and search on DLsite and DDG. Then it will fetch the search result and rename the folder with[YYMMDD][RJ NUMBER][AUTHOR]GAME NAME. It features a web portal for you to review the result. The accuracy is ~50%. I suggest start with this and perceed with each version of renamer, in each run you correct them manually bu reverse the previous name in the web portal.  

./game_renamer_DDG remove the dlsite search part, only DDG.  

./game_renamer_DDGEXE remove the dlsite search part, only DDG and the .exe title.  

./game_renamer_DDGF remove the dlsite search part, only DDGDDG and the folder name.  

./rename_viewer.py the web portal. No need to run.  


/E-hentai:   

./cookie your cookies of Exhentai and Nhentai.  

./config.json parent dir for the scripts.   

./src/Process_gallery.py: Select a parent folder path, rename images in each folder in parent folder to %08d format(00000001.jpg, 00000002.jpg, etc.), If info.txt from Ehentai dowenloader exists, parse it to generate ComicInfo.xml for EhViewer, If theres no info.txt, search ExHentai/NHentai to get metadata with title.   

./src/Manual_xml.py: Manually extract ComicInfo.xml from ExHentai gallery URL. It loops through gallery folders in a parent directory and prompts for URLs. Once URLs from Exhentai is provided a comicinfo.xml is generated.  

./src/folder_to_cbz.py: compress the manga folder to .cbz(for my EhViewer_Grid).

/FANZA:   

working on it
