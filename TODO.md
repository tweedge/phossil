# TODO

Yes I'm keeping notes here

## data storage changes
* rework initial phishing DDB revamp
* what I want for the initial phishing db
* key: source#url (or a hash idc)
* source
* url
* first seen in THIS SYSTEM epoch
* verified y/n (phish score VERY high from phishstats, or phishtank verified, etc.)
* optional: update the verified value if it increases from no to yes?

* relationship DDB revamp
* is it possible to to a put/update as one?

## nitpicks
* change the list of files that are being saved
  * consider cutting down on docs or things you don't know are going to be useful
* figure out what browser behavior would be tolerable for a phish site (or just don't care, alternatively)
* decide whether or not to require 200s for even the Big Downloads
* everyond doesn't need to be in `lambdas/`

## architecture changes
* rereading docs I think a FIFO queue is really not going to be useful here
* reimplement roles to be a smidge more permissive to cut down on toil
* really debating whether or not tracking all hrefs is going to be useful
* should there be any rescan logic to pick up more data later?

## future work
* optional event read to make it easier to run the entire list, instead of a subset for ALL lambdas
* onboard new data stores (OpenPhish and PhishStats)
* dashboards! alarms!
  * data growth alarms in case someone tries retaliating with a bunch of 9GB files
* submit executables to VT/MalShare/etc. automatically because fuck you
* should collect emails from kits if possible to report those semiautomatically
* learn from: https://github.com/t4d/StalkPhish/blob/master/stalkphish/tools/download.py
  * carefully weigh complexity vs fun vs differentiation
  * stalkphish covers targets comprehensively and should be recommended for investigators, it's OK if I cover targets only for obvious mistakes
  * ex. cloudflare bot bypass is trivial via cfscrape but needs maintenance long-term
* use git or subversion in scans & figure out how to archive these
* version my lambdas in git properly once the architecture is more stable
* learn from: https://github.com/t4d/PhishingKitHunter
  * hash phishing kit pages, maybe more useful than the links
* integrate? https://github.com/t4d/PhishingKit-Yara-Rules
  * could periodic scan all zips I have with this