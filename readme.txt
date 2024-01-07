@app.route('/list/<name>/update', methods=['GET', 'POST'])
def update(name):
    contestant = contestants.query.filter(contestants.name.ilike(name)).first()
    
    if not contestant:
        print(f"Contestant with name '{name}' not found.")
        return redirect('/list')

    new_score = contestant.scores

    if request.method == 'POST':
        new_score = int(request.form.get('scores'))
        contestant.scores = new_score
        db.session.commit()

        return redirect('/list')

    print(f"Contestant found: {contestant}")
    return render_template('update.html', new_scores=new_score)
