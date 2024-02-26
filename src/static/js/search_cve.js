const searchInput = document.getElementById('search-input');
const searchButton = document.getElementById('search-button');
const deleteIcon = document.querySelector('.delete-icon');

function extractNumberFromURL() {
    const segments = window.location.pathname.split('/');
    let lastSegment = segments[segments.length - 1];

    const ipv4Pattern = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (!ipv4Pattern.test(lastSegment)) {
        lastSegment = segments[segments.length - 2];
    }
    return lastSegment;
}

searchInput.addEventListener('keypress', function (event) {
    if (event.key === "Enter") {
        redirectToUrl();
    }
});

function redirectToUrl() {
    var inputVal = document.getElementById("search-input").value;
    if (inputVal) {
        window.location.href = "/report/" + extractNumberFromURL() + "/search=" + encodeURIComponent(inputVal);
    }
}


// Function to handle delete icon click
deleteIcon.addEventListener('click', () => {
    searchInput.value = '';

    const segments = window.location.pathname.split('/');
    let urlParams = segments[segments.length - 1];
    if (urlParams.includes('search=')) {
        const ip = extractNumberFromURL()
        window.location.href = '/report/' + ip;
    }

});

// Function to handle input change
searchInput.addEventListener('input', () => {
    updateDeleteIconVisibility();
});

// Function to update visibility of delete icon
function updateDeleteIconVisibility() {
    if (searchInput.value !== '') {
        deleteIcon.style.display = 'block';
    } else {
        deleteIcon.style.display = 'none';
    }
}

