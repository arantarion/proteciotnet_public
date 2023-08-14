const searchInput = document.getElementById('search-input');
const searchButton = document.getElementById('search-button');
const deleteIcon = document.querySelector('.delete-icon');

function extractNumberFromURL() {
    const segments = window.location.pathname.split('/');
    let lastSegment = segments[segments.length - 1];

    const ipv4Pattern = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if  (!ipv4Pattern.test(lastSegment)) {
        lastSegment = segments[segments.length - 2];
    }
    return lastSegment;
}


// Function to handle search button click
searchButton.addEventListener('click', () => {
    const searchTerm = searchInput.value.trim(); // Get and trim the search term
    if (searchTerm !== '') {
        const currentNumber = extractNumberFromURL();
        window.location.href = `/report/${currentNumber}/search/${encodeURIComponent(searchTerm)}`; // Navigate to the internal URL
    }
});

// Function to handle delete icon click
deleteIcon.addEventListener('click', () => {
    searchInput.value = '';
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

