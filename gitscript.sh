set +x

if [ -e result.csv ]; then
   echo file exists
   rm result.csv
else
   echo file does not exist or is not executable
fi
touch result.csv

sort /var/lib/jenkins/github_repos_backup/sorted_github_repos.txt | grep -v mda-config | uniq > ${WORKSPACE}/sorted_github_repos.txt
echo "\033[1m========Getting list of Repositories=====\033[0m"


echo "Repo,Branch,Commit_id,Author,Regex,Instances,Result" >> ${WORKSPACE}/result.csv

vuls='.........\.[Dd][Bb][^=:]*[:=].*,
ssh-rsa*.*,
[p|P][a|A][s|S][s|S].*\=.*.
[p|P][a|A][s|S][s|S].*\:.*.
[p|P][a|A][s|S].*\:.*.
.secret.*.
.*_rsa
.*_dsa
.*_ed25519
.*_ecdsa
.?ssh/config
.pem
.?mysql_history
.?s3cfg
.?aws/credentials
private.*key
AKIA[0-9A-Z]
AGPA[0-9A-Z]
AIDA[0-9A-Z]
AIPA[0-9A-Z]
ANPA[0-9A-Z]
ANVA[0-9A-Z]
ASIA[0-9A-Z]
AIza[0-9A-Za-z\\-_]
.?htpasswd
jenkins.plugins.publish_over_ssh.BapSshPublisherPlugin.xml
hooks.slack.com
gainsight.slack.com
crypt_key.*=.*.\w'


echo ""
echo -e "\033[1m==========================[START]=========================================\033[0m"
echo ""



pushd /var/lib/jenkins/github_repos_backup > /dev/null

echo -e "\033[1m Moving to github_repos_backup ===\033[0m"

cat ${WORKSPACE}/sorted_github_repos.txt | while read repo 
do
   echo "Repo name: $repo"
   commitlog="${WORKSPACE}/${repo}commit.log"
   if [[ -d ${repo} ]]; then
       echo "Repository already exists ..."
	   pushd ${repo}  > /dev/null
   else
	   echo "Repository does not exist in the workspace, Creating Repostiory .."
	   echo ""
	   #git clone ${github_url}/${repo}
       pushd ${repo}  > /dev/null
	   echo ""
   fi
   
   set -e
   git checkout release || true
   set +e
   git log --pretty=format:"%H %ad %ae %an" --date=iso --since=1.days > ${commitlog}
   
   if [ -s "${commitlog}" ]; then 
       echo "New commits exists."
       echo "" >> ${commitlog}
       cat ${commitlog} | while read commit
	   do
		   commit_id=$(echo $commit | awk  '{print $1}')
		   author=$(echo $commit | awk  '{print $5}')
		   echo "Checking out to :$commit_id by $author"
		   git checkout $commit_id
           for vulnerability in `echo "${vuls}" | tr "," "\n"`; do
			    echo "Scanning for ${vulnerability}"
                #git diff-tree --no-commit-id --name-only -r $commit_id
			    grep --exclude=temp.txt -rno `git diff-tree --no-commit-id --name-only -r $commit_id` -e "${vulnerability}" | sed -e "s/,//g;s/MONGO_GLOBAL_PASSWORD//g;s/dbNameUsed//g;s/POSTGRESQL_SHARED_PASSWORD//g;s/redshift.junit.password//g;s/cockpit.rabbitmq.password.env//g;s/secretDataReader//g;s/db.queue.route.mongo.password//g;s/db.queue.password//g;s/Password(postgresInfo.getPassword//g;s/passedpassed//g;s/PassedSinceDisable//g;s/passwordByte//g;s/workerDeploy.sh//g;s/ra.dbResourceAttributes//g;s/PASS_COUNT//g;s/ssh_host_rsa//g;s/dbResourceAttributes//g;s/pAssignedOnCollection//g" > temp.txt
			    if [ -s "temp.txt" ]; then
			        echo "->Match found."
                    cat temp.txt
			        branch=$(git branch | sed -n -e 's/^\* \(.*\)/\1/p' | sed -e "s/,//g")
			        score=$(cat temp.txt | wc -l)
			        result=$(paste -sd\\t temp.txt)
			        echo "$repo,$branch,$commit_id,$author,$vulnerability,$score,\"$result\"" >> ${WORKSPACE}/result.csv
			    else
			     echo "No Match found for $vulnerability."
			    fi
	        done
            rm temp.txt
	   done 

   else
       echo "No new commit found."
   fi
   rm ${commitlog}
   echo ""
   

   popd  > /dev/null
done

popd  > /dev/null


cat ${WORKSPACE}/result.csv 
echo $(cat ${WORKSPACE}/result.csv | wc -l)

if [ $(cat ${WORKSPACE}/result.csv | wc -l) -ge 2 ]; then
echo "XSS has been detected."
else
echo "No XSS has detected."
exit 1
fi
