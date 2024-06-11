
fetch("/getLast-history").then(r=>r.json())
.then(data=>{
    let history = data.historique
    document.querySelector("#nb_disc").innerHTML = history.length + " traduction" + (history.length>1?"s":"") +"<br> Aujhourd'hui"
    for(let hist of history){
        let htm = `
            <div class="d-flex justify-content-end mb-4">
                <div class="msg_cotainer_send">
                    ${hist.text_origin}
                    <span class="msg_time_send">Toi, ${formatAMPM(new Date(hist.translated_at))}</span>
                </div>
                <div class="img_cont_msg">
                    <img src="https://static.turbosquid.com/Preview/001292/481/WV/_D.jpg"
                        class="rounded-circle user_img_msg">
                </div>
            </div>

            <div class="d-flex justify-content-start mb-4">
                <div class="img_cont_msg">
                    <img src="/static/image/ai.png"
                        class="rounded-circle user_img_msg">
                </div>
                <div class="msg_cotainer">
                    ${hist.translated_text}
                    <span class="msg_time">${formatAMPM(new Date(hist.translated_at))}</span>
                </div>
            </div>
        `

        document.querySelector("#discussion")? document.querySelector("#discussion").innerHTML +=htm :""
    }
})

const queryString = window.location.href;
// const urlParams = new URLSearchParams(queryString);
// const key = urlParams.get('key')
let parts = queryString.split('/')
let key = parts[parts.length - 1]

// console.log(key);

if(key){
    key = getDateFromHexa(key);
    console.log(key);
    const year = key.substring(0, 4);
    const month = key.substring(4, 6);
    const day = key.substring(6, 8);

    // Reconstituez la date avec les parties séparées par des tirets
    const formattedDateStr = `${year}-${month}-${day}`;

    fetch("/getAll-history-byDate?key="+key).then(r=>r.json())
    .then(data=>{
        let history = data.historique
        document.querySelector("#nb_disc").innerHTML = history.length + " traduction" + (history.length>1?"s":"") +"<br>"+estAujourdhuiOuHier(new Date(formattedDateStr))
        for(let hist of history){
            let htm = `
                <div class="d-flex justify-content-end mb-4">
                    <div class="msg_cotainer_send">
                        ${hist.text_origin}
                        <span class="msg_time_send">Toi, ${formatAMPM(new Date(hist.translated_at))}</span>
                    </div>
                    <div class="img_cont_msg">
                        <img src="https://static.turbosquid.com/Preview/001292/481/WV/_D.jpg"
                            class="rounded-circle user_img_msg">
                    </div>
                </div>
    
                <div class="d-flex justify-content-start mb-4">
                    <div class="img_cont_msg">
                        <img src="/static/image/ai.png"
                            class="rounded-circle user_img_msg">
                    </div>
                    <div class="msg_cotainer">
                        ${hist.translated_text}
                        <span class="msg_time">${formatAMPM(new Date(hist.translated_at))}</span>
                    </div>
                </div>
            `
    
            document.querySelector("#discussion_specific")?document.querySelector("#discussion_specific").innerHTML +=htm :""
        }
    })
    
}

fetch("/getAllGroupedByDate").then(r=>r.json())
.then(data=>{
    let i = 0;
    for(let trans of data){

        document.querySelector("#contacts_body").innerHTML += `
            <li class="${trans.date.replaceAll("-","") == key?"active":(i==0 && trans.length==1?"active":"")}">
                <div class="d-flex bd-highlight">
                    <div class="img_cont">
                        <img src="/static/image/ai.png"
                            class="rounded-circle user_img">
                        <span class="online_icon"></span>
                    </div>
                    <div class="user_info">
                        <!--<a href="?key=${trans.key}"><span>${trans.text_origin}</span></a>-->
                        <a href="/${dateToHexa(trans.key)}"><span>${trans.text_origin}</span></a>
                        <p>${trans.date}<br><i class="text-warning">${trans.count} traduction${trans.count>1?'s':''}</i></p>
                        
                    </div>
                </div>
            </li>
        `
        i++;
    }
})

async function translateText() {
    const text = document.getElementById('text-to-translate').value;

    let htm = `
        <div class="d-flex justify-content-end mb-4">
            <div class="msg_cotainer_send">
                ${text}
                <span class="msg_time_send">Toi, ${formatAMPM(new Date())}</span>
            </div>
            <div class="img_cont_msg">
                <img src="https://static.turbosquid.com/Preview/001292/481/WV/_D.jpg"
                    class="rounded-circle user_img_msg">
            </div>
        </div>
    `
    document.querySelector("#discussion")?document.querySelector("#discussion").innerHTML +=htm :""
    document.querySelector("#discussion_specific")? document.querySelector("#discussion_specific").innerHTML +=htm :""


    const response = await fetch('/translate', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ text: text })
    });
    const data = await response.json();

    let res = `
        <div class="d-flex justify-content-start mb-4">
            <div class="img_cont_msg">
                <img src="/static/image/ai.png"
                    class="rounded-circle user_img_msg">
            </div>
            <div class="msg_cotainer">
                ${data.translated_text}
                <span class="msg_time">${formatAMPM(new Date())}</span>
            </div>
        </div>
    `

    

    document.querySelector("#discussion")?document.querySelector("#discussion").innerHTML +=res :""
    document.querySelector("#discussion_specific")? document.querySelector("#discussion_specific").innerHTML +=res :""

    document.getElementById('text-to-translate').value = ""

    // document.getElementById('translated-text').innerText = data.translated_text;
}

function formatAMPM(date) {
    var hours = date.getHours();
    var minutes = date.getMinutes();
    var ampm = hours >= 12 ? 'PM' : 'AM';
    hours = hours % 12;
    hours = hours ? hours : 12; // the hour '0' should be '12'
    minutes = minutes < 10 ? '0'+minutes : minutes;
    var strTime = hours + ':' + minutes + ' ' + ampm;
    // return strTime + ", " + estAujourdhuiOuHier(date);
    return strTime;
  }


  // Fonction pour vérifier si une date est aujourd'hui, hier ou il y a x jours
function estAujourdhuiOuHier(date) {
    // Date actuelle
    var dateActuelle = new Date();
    
    // Aujourd'hui
    var aujourdhui = new Date(dateActuelle.getFullYear(), dateActuelle.getMonth(), dateActuelle.getDate());
    
    // Hier
    var hier = new Date(dateActuelle.getFullYear(), dateActuelle.getMonth(), dateActuelle.getDate() - 1);
    
    // Comparaison
    if (date.toDateString() === aujourdhui.toDateString()) {
        return "Aujourd'hui";
    } else if (date.toDateString() === hier.toDateString()) {
        return "Hier";
    } else {
        var difference = (dateActuelle.getTime() - date.getTime()) / (1000 * 60 * 60 * 24); // Différence en jours
        return "Il y a " + Math.floor(difference) + " jour" +(Math.floor(difference)>2?"s":"");
    }
}

function isoToEmoji(code){
    return code.split('')
    .map(lettre => lettre.charCodeAt(0) % 32 + 0x1F1E5)
    .map(n => String.fromCodePoint(n)).join('');
}

$(document).ready(function () {
    $('#action_menu_btn').click(function () {
        $('.action_menu').toggle();
    });

    let FK_b05SbbY = document.querySelector('#sessionKey').value

    if(FK_b05SbbY == null || FK_b05SbbY == "False"){

        $('#loginModal').modal('show');
    }

});


function dateToHexa(dateInput) {
    // Transformer chaque chiffre en combinant avec des caractères et des tirets
    let part1 = dateInput[0] + 'a' + dateInput[1] + 'c' + dateInput[2] + 'a' + dateInput[3] + 'b';
    let part2 = dateInput[4] + 'c' + dateInput[5] + dateInput[6] + 'd';
    let part3 = dateInput[7] + 'c';
    
    let combined = part1 + '-' + part2 + '-' + part3 +'-e07712edd737';
    // document.getElementById('combinedText').innerText = combined;
    return combined;
}

function getDateFromHexa(dateInput) {
    return dateInput.replaceAll("-e07712edd737","").replaceAll(/\D/g,"")
}

if(document.querySelector(".toggle-password")){
    document.querySelector(".toggle-password").addEventListener("click",function(e){
        console.log(e.previousElementSibling);
    })
}

function sendMailForgot(){
    let email = document.querySelector("#email-forgot").value;
    fetch("/send-reset-email",{
        method:"POST",
        headers:{
            "Content-Type":"application/json"
        },
        body:JSON.stringify({email:email})
    })
   .then(r=>r.json())
   .then(data => {
        if (data.success) {
            alert('Password reset email sent successfully.');
        } else {
            alert('An error occurred: ' + data.message);
        }
    })
    .catch(error => {
        console.error('Error:', error);
    });
}

function showProfil(){
    fetch("/profil")
    .then(r=>r.json())
    .then(data=>{
        document.querySelector("#name_profil").textContent = data.username
        document.querySelector("#email_profil").textContent = data.email
        console.log(data);
    })
}